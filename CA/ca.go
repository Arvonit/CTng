package CA

import (
	//"CTng/crypto"
	//"CTng/gossip"
	"CTng/util"
	cr "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	//"encoding/json"
	"errors"
	"fmt"
	"bytes"
	"math/big"
	"time"
	"net/http"
	"log"
	"strconv"
	"encoding/json"


	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"


func GenerateSelfSigned(ca *CAContext) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	cn := ca.Config.Signer
	isCA := true

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	issuer := &template
	issuerKey := ca.Config.Crypto.RSAPrivateKey

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, issuer, issuerKey.Public(), &issuerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func convertRSAToCrypto(rsaKey rsa.PrivateKey) cr.PrivateKey {
	return rsaKey
}

func GeneratePrecert(domain string, isCA bool, ca *CAContext) (*x509.Certificate, cr.PrivateKey, error) {
	// priv, err := rsa.GenerateKey(rand.Reader, 2048)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	issuer := ca.IssuerCertificate
	issuerKey := ca.Config.Crypto.RSAPrivateKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &issuer, priv.Public(), &issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	curr_size := ca.Certificates.GetSizeOfCertPool()
	vectorNumber := curr_size / ca.Config.Public.Length
	var indexInVector uint64 = curr_size % ca.Config.Public.Length

	revocationPlace := util.Place{
		Vector: int(vectorNumber),
		Index:  int(indexInVector),
	}
	revocationPlaceToBytes, err := asn1.Marshal(revocationPlace)
	if err != nil {
		return nil, nil, err
	}
	cert.Extensions = append(cert.Extensions, pkix.Extension{
		Id:       util.REVOKE_EXTENSION_ID,
		Critical: true,
		Value:    revocationPlaceToBytes,
	})
	ca.Certificates.AddCert(cert)
	return cert, priv, nil
}

/*
:param CAContext ca: contains the information about the current state of the CA including configuration files
:param x509.Certificate crt: the new certficiate that will be added to the ca
:description: Find the right place in the crv to add the new certificate and add it
*/
func AddCertificateToRevocator(ca *CAContext, domain string) error {
	crt, _, err := GeneratePrecert(domain, false, ca)
	if err != nil {
		fmt.Println((err))
		return err
	}
	var revPlace = util.FindRevokePlace(crt)

	if revPlace.Vector >= len(ca.Revocators) {
		var new_revocator Revocator = &CRV{
			Vector:   bitarray.NewBitArray(1),
			DeltaVec: bitarray.NewBitArray(1),
			CASign: tls.DigitallySigned{
				Algorithm: tls.SignatureAndHashAlgorithm{
					Hash:      tls.SHA256,
					Signature: tls.RSA,
				},
				Signature: []byte("0"),
			},
			LoggerSign: tls.DigitallySigned{
				Algorithm: tls.SignatureAndHashAlgorithm{
					Hash:      tls.SHA256,
					Signature: tls.RSA,
				},
				Signature: []byte("0"),
			},
			Length: ca.Config.Public.Length,
		}

		ca.Revocators = append(ca.Revocators, &new_revocator) // new(Revocator)
	}
	result_str := "added certificate for the domain: " + domain + "\n" +
		"revcation place: (Vector: " + fmt.Sprint(revPlace.Vector) + ",Index: " + fmt.Sprint(revPlace.Index) + ")" + "\n" +
		"SerialNumber: " + fmt.Sprint(crt.SerialNumber) + "\n" +
		"NotBefore: " + fmt.Sprint(crt.NotBefore) + "\n" +
		"NotAfter: " + fmt.Sprint(crt.NotAfter) + "\n" +
		"IsCA: " + fmt.Sprint(crt.IsCA) + "\n" +
		"PublicKey: " + fmt.Sprint(crt.PublicKey) + "\n" +
		"PublicKeyAlgorithm: " + fmt.Sprint(crt.PublicKeyAlgorithm)
	return errors.New(result_str)
}

/*
:param CAContext ca: contains the information about the current state of the CA including configuration files
:param x509.Certificate crt: the new certficiate that will be revoked by the ca
:description: Find the right place in the crv and set the bit to 1
*/
// revoke certifiace by deomain name
func RevokeCertificate(ca *CAContext, domain string) error {
	// search the cert by its name
	cert := ca.Certificates.GetCertByName(domain)
	if cert == nil {
		return errors.New("there is not certificate for the domain: " + domain)
	}
	// check if already revoked
	var revPlace *util.Place = util.FindRevokePlace(cert)
	is_revoked, _ := (*ca.Revocators[revPlace.Vector]).IsRevoked(cert)
	if is_revoked {
		return errors.New("the certficate of the domain: " + domain + " already revoked")
	}
	(*ca.Revocators[revPlace.Vector]).RevokeCertificate(cert)
	return errors.New("revoked the certificate of the domain: " + domain)
}

/*
:param CAContext ca: contains the information about the current state of the CA including configuration files
:return Gossip_object gossipREV: this object conatins array of byte[] arrays, each of byte arrays is delta crv of one of the Revocators od the CA
:description: Generate delta CRV and then compress it
*/

/*
func GenerateDeltaCRV(ca *CAContext) gossip.Gossip_object {
	// var compressed_deltas [][]byte
	var compressed_deltas [][]byte
	for i, _ := range ca.Revocators {
		delta_crv := (*ca.Revocators[i]).GetDelta()
		fmt.Println("vector:", util.BitsToBytes((*ca.Revocators[i]).GetVector()))
		fmt.Println("delta:", util.BitsToBytes(delta_crv))
		// compressed_deltas = append(compressed_deltas, GZip.Compress(util.BitsToBytes(delta_crv)))
		compressed_deltas = append(compressed_deltas, util.BitsToBytes(delta_crv))
	}
	vectors_hash, err := crypto.GenerateHashOnVectors(ca.Revocators)
	if err != nil {
		fmt.Println(err)
		fmt.Println("can not generate hash on the crv vectors")
	}
	// fmt.Println(util.BitsToBytes(compressed_deltas[0]))
	REV := Revocation{
		Signer:       ca.Config.Signer,
		Delta_CRV:    compressed_deltas,
		Vectors_Hash: vectors_hash,
		Timestamp:    gossip.GetCurrentTimestamp(),
		Period:       ca.Current_Period,
	}
	fmt.Println(REV)
	// fmt.Println(util.BitsToBytes(REV.Delta_CRV[0]))
	//transforms the memory representation of the revocation object into a data format suitable for transmission
	payload, _ := json.Marshal(REV)

	fmt.Println("after unmarshal:")
	var rev Revocation
	json.Unmarshal(payload, &rev)
	fmt.Println(rev)
	//add sign of the CA on the revocation data
	signature, _ := crypto.RSASign([]byte(payload), &ca.Config.Crypto.RSAPrivateKey, crypto.CTngID(ca.Config.Signer))
	gossipREV := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.REVOCATION,
		Signer:      ca.Config.Signer,
		Signature:   [2]string{signature.String(), ""},
		Timestamp:   REV.Timestamp,
		Payload:     [2]string{string(payload), ""},
	}
	// fmt.Println(gossipREV.Payload[0])
	return gossipREV
}
*/

/*
:param: None
description: this function  wiil run always in the background as a go routine process and will do the periodic taks of the CA
	this function occurs every MRD
*/
func PeriodicTasks(ca *CAContext) {
	// Immediately queue up the next task to run at next MRD
	f := func() {
		PeriodicTasks(ca)
	}
	// Run the periodic tasks.
	time.AfterFunc(time.Duration(ca.Config.Public.MRD)*time.Second, f)

	// Generate CRV and SRH
	fmt.Println("Running CA's Tasks")
	// Send to the loggers the current period revocation information  (this occurs every MRD)
	//Rev_info := GenerateDeltaCRV(ca)
	//ca.SRHs = append(ca.SRHs, Rev_info) // add the new rev info to the SRHs array of the ca (signed revocation head), the CA saves all the information it sends

	/*
		// Convert gossip object to JSON
		msg, err := json.Marshal(Rev_info)
		if err != nil {
			fmt.Println(err)
		}
		// Send the revocation info (as gossip object) to all the loggers connected to the ca
		for _, logger_url := range ca.Config.Logger_URLs {
			resp, postErr := ca.Client.Post("http://"+logger_url+"/logger/receive-srh", "application/json", bytes.NewBuffer(msg))
			if postErr != nil {
				fmt.Println("Error sending srh to logger: " + postErr.Error())
			} else {
				// Close the response, mentioned by http.Post
				// Alernatively, we could return the response from this function.
				defer resp.Body.Close()
				fmt.Println("Logger responded with " + resp.Status)
			}
			// Handling errors from owner could go here.
		}
	*/
	ca.Current_Period++
}

// Test the add certifiacte mechanism
func AddCertificateTest(ca *CAContext) {
	fmt.Println(ca.Certificates.GetSizeOfCertPool())
	cert, _, err := GeneratePrecert("google.com", false, ca)
	if err != nil {
		fmt.Println((err))
	}

	fmt.Println(cert.Subject.CommonName)

	var p *util.Place = util.FindRevokePlace(cert)
	println(p.Vector, p.Index)

	fmt.Println(ca.Certificates.GetSizeOfCertPool())

	cert, _, err = GeneratePrecert("ynet.co.il", false, ca)
	if err != nil {
		fmt.Println((err))
	}
	fmt.Println(cert.Subject.CommonName)
	p = util.FindRevokePlace(cert)
	println(p.Vector, p.Index)

	fmt.Println(ca.Certificates.GetSizeOfCertPool())

}

// Binds the context to the functions we pass to the router.
func bindCAContext(context *CAContext, fn func(context *CAContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleCARequests(ca *CAContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)

	// POST functions
	//gorillaRouter.HandleFunc("/ca/sendCert", bindCAContext(ca, sendCert)).Methods("POST")
	gorillaRouter.HandleFunc("/ca/add-certificate", bindCAContext(ca, addCert)).Methods("GET")
	gorillaRouter.HandleFunc("/ca/revoke-certificate", bindCAContext(ca, revCert)).Methods("GET")
	gorillaRouter.HandleFunc("/ca/get-revocations", bindCAContext(ca, getRevocations)).Methods("GET")
	gorillaRouter.HandleFunc("/ca/get-period", bindCAContext(ca, getCAPeriod)).Methods("GET")

	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	fmt.Println("Listening on port", ca.Config.Port)
	log.Fatal(http.ListenAndServe("localhost:"+ca.Config.Port, nil))
}
func SendCert(c *CAContext, cert *x509.Certificate){
	msg, err := json.Marshal(cert)
	if err != nil {
		fmt.Println(err)
	}
	// Send the gossip object to the gossiper
	for _,logger :=  range(c.Config.Logger_URLs){
		resp, postErr := c.Client.Post(PROTOCOL+logger+"/ctng/v2/send-sth", "application/json", bytes.NewBuffer(msg))
		if postErr != nil {
			fmt.Println(util.RED+"Error sending object to Gossiper: ", postErr.Error(),util.RESET)
			return
		} else {
			// Close the response, mentioned by http.Post
			// Alernatively, we could return the response from this function.
			defer resp.Body.Close()
			fmt.Println(util.BLUE+"Sent"+ util.RESET)
		}
	}
	
}
func getCAPeriod(c *CAContext, w http.ResponseWriter, req *http.Request) {
	fmt.Println("get CA's current period")
	// Convert array of gossip objects to JSON
	msg, err := json.Marshal(c.Current_Period)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(msg)
	return
}

func getRevocations(c *CAContext, w http.ResponseWriter, req *http.Request) {
	fmt.Println("get revocations")
	startPeriod, ok := req.URL.Query()["startPeriod"]
	if !ok {
		http.Error(w, "missing start period argument", http.StatusBadRequest)
		return
	}
	numStartPeriod, err := strconv.Atoi(startPeriod[0])
	if err != nil || numStartPeriod < 0 {
		http.Error(w, "start period argument should be a positive number", http.StatusBadRequest)
		return
	}

	endPeriod, ok := req.URL.Query()["endPeriod"]
	if !ok {
		http.Error(w, "missing end period argument", http.StatusBadRequest)
		return
	}
	numEndPeriod, err := strconv.Atoi(endPeriod[0])
	if err != nil || numEndPeriod < 0 || numEndPeriod < numStartPeriod || numEndPeriod >= c.Current_Period {
		http.Error(w, "end period argument should be a positive number bigger than the start period argument", http.StatusBadRequest)
		return
	}
	srhsToSend := c.SRHs[numStartPeriod : numEndPeriod+1]
	// Convert array of gossip objects to JSON
	msg, err := json.Marshal(srhsToSend)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(msg)
	return
}

//  msg, err := json.Marshal(g)
//	resp, postErr := c.Client.Post(PROTOCOL+c.Config.Gossiper_URL+"/gossip/gossip-data", "application/json", bytes.NewBuffer(msg))
func addCert(c *CAContext, w http.ResponseWriter, req *http.Request) {
	fmt.Println("add certificate")
	fmt.Println(c.Revocators[0])
	domain, ok := req.URL.Query()["domain"]
	if !ok || len(domain[0]) < 1 {
		http.Error(w, "no input", http.StatusOK)
		return
	}
	result := AddCertificateToRevocator(c, domain[0])
	http.Error(w, result.Error(), http.StatusOK)
}

func revCert(c *CAContext, w http.ResponseWriter, req *http.Request) {
	domain, ok := req.URL.Query()["domain"]
	if !ok || len(domain[0]) < 1 {
		fmt.Fprintf(w, "error")
		return
	}
	result := RevokeCertificate(c, domain[0])
	http.Error(w, result.Error(), http.StatusOK)
}

// Run CA server
// Note that the monitor configurations must include then CA's Public key and ID as trusted
func StartCAServer(c *CAContext) {
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// ca.AddCertificateTest(c)
	// Run a go routine to handle tasks that must occur every MRD
	go PeriodicTasks(c)
	// Start HTTP server loop on the main thread
	handleCARequests(c)
}
