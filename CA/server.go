package CA

import (
	"CTng/gossip"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	"fmt"

	//"io/ioutil"
	"crypto/x509"
	"log"
	"net/http"
	"time"

	//"strings"
	"bytes"
	"crypto/rsa"
	"io/ioutil"
	"strconv"

	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"

//bind CA context to the function
func bindCAContext(context *CAContext, fn func(context *CAContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleCARequests(c *CAContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions

	// Comments: RID should be received right after the precert is sent to the logger
	// STH and POI should be received at the end of each period
	// receive STH from logger
	gorillaRouter.HandleFunc("/CA/receive-sth", bindCAContext(c, receive_sth)).Methods("POST")
	// receive POI from logger
	gorillaRouter.HandleFunc("/CA/receive-poi", bindCAContext(c, receive_poi)).Methods("POST")
	// receive get request from monitor
	gorillaRouter.HandleFunc("/ctng/v2/get-revocation", bindCAContext(c, requestREV)).Methods("GET")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.CA_private_config.Port, nil))
}

// receive get request from monitor
func requestREV(c *CAContext, w http.ResponseWriter, r *http.Request) {
	Period := gossip.GetCurrentPeriod()
	c.Request_Count++
	switch c.CA_Type {
	case 0:
		//normal CA
		json.NewEncoder(w).Encode(c.REV_storage[Period])
		return
	case 1:
		//split-world CA
		if c.Request_Count%c.MisbehaviorInterval == 0 {
			json.NewEncoder(w).Encode(c.REV_storage_fake[Period])
		} else {
			json.NewEncoder(w).Encode(c.REV_storage[Period])
		}
		return
	case 2:
		//always unresponsive CA
		return
	case 3:
		//sometimes unresponsive CA
		if c.Request_Count%c.MisbehaviorInterval == 0 {
			return
		} else {
			json.NewEncoder(w).Encode(c.REV_storage[Period])
		}
	}
}

// receive STH from logger
func receive_sth(c *CAContext, w http.ResponseWriter, r *http.Request) {
	// Read the request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	// Unmarshal the request body into a STH
	var gossip_sth gossip.Gossip_object
	err = json.Unmarshal(body, &gossip_sth)
	if err != nil {
		panic(err)
	}
	//fmt.Println("STH received from logger: ", gossip_sth.Signer)
	// Verify the STH
	err = gossip_sth.Verify(c.CA_crypto_config)
	if err != nil {
		panic(err)
	}
	// Update the STH storage
	//fmt.Println("STH passed verification")
	c.STH_storage[gossip_sth.Signer] = gossip_sth
	fmt.Println("STH storage: ", c.STH_storage)
}

// receive POI from logger
func receive_poi(c *CAContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into [][]byte
	var poi POI
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&poi)
	if err != nil {
		panic(err)
	}
	//fmt.Println("Logger ID in this poi: ", poi.LoggerID)
	// Verify the POI
	// Get the STH of the logger
	sth := c.STH_storage[poi.LoggerID]
	//fmt.Println("sth: ", sth, c.STH_storage)
	// Construct the CTng extension
	extension := CTngExtension{
		STH: sth,
		POI: poi.ProofOfInclusion,
	}
	target_cert := c.CurrentCertificatePool.GetCertBySubjectKeyID(string(poi.SubjectKeyId))
	if target_cert != nil {
		fmt.Println(poi.SubjectKeyId)
		target_cert = AddCTngExtension(target_cert, extension)
		c.CurrentCertificatePool.UpdateCertBySubjectKeyID(string(poi.SubjectKeyId), target_cert)
	}
}

//send a signed precert to a logger
func Send_Signed_PreCert_To_Logger(c *CAContext, precert *x509.Certificate, logger string) {
	precert_json := Marshall_Signed_PreCert(precert)
	//fmt.Println(precert_json)
	//fmt.Println(logger)
	//fmt.Println(precert_json)
	resp, err := c.Client.Post(PROTOCOL+logger+"/Logger/receive-precerts", "application/json", bytes.NewBuffer(precert_json))
	if err != nil {
		fmt.Println("Failed to send precert to loggers: ", err)
	}
	defer resp.Body.Close()
}

// send a signed precert to all loggers
func Send_Signed_PreCert_To_Loggers(c *CAContext, precert *x509.Certificate, loggers []string) {
	//fmt.Println(loggers)
	for i := 0; i < len(loggers); i++ {
		precert_json := Marshall_Signed_PreCert(precert)
		//fmt.Println(precert_json)
		//fmt.Println(loggers[i])
		resp, err := c.Client.Post(PROTOCOL+loggers[i]+"/Logger/receive-precerts", "application/json", bytes.NewBuffer(precert_json))
		if err != nil {
			fmt.Println("Failed to send precert to loggers: ", err)
		} else {
			defer resp.Body.Close()
		}
	}
}

func wipeSTHstorage(c *CAContext) {
	for k := range c.STH_storage {
		delete(c.STH_storage, k)
	}
}

func SignAllCerts(c *CAContext) []x509.Certificate {
	root := c.Rootcert
	priv := c.CA_crypto_config.RSAPrivateKey
	certs := c.CurrentCertificatePool.GetCerts()
	var signed_certs []x509.Certificate
	for i := 0; i < len(certs); i++ {
		cert := certs[i]
		pub := cert.PublicKey
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			// handle the case where pub is not of type *rsa.PublicKey
		}
		signed_cert := Sign_certificate(&cert, root, false, rsaPub, &priv)
		signed_certs = append(signed_certs, *signed_cert)
	}
	return signed_certs
}

func GetCurrentPeriod() string {
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Miniutes, err := strconv.Atoi(timerfc[14:16])
	Periodnum := strconv.Itoa(Miniutes)
	if err != nil {
	}
	return Periodnum
}

func GerCurrentSecond() string {
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Second, err := strconv.Atoi(timerfc[17:19])
	Secondnum := strconv.Itoa(Second)
	if err != nil {
	}
	return Secondnum
}

func PeriodicTask(ctx *CAContext) {
	f := func() {
		PeriodicTask(ctx)
	}
	time.AfterFunc(time.Duration(ctx.CA_public_config.MMD)*time.Second, f)
	fmt.Println("——————————————————————————————————CA Running Tasks at Period ", GetCurrentPeriod(), "——————————————————————————————————")
	// wipe STH storage
	wipeSTHstorage(ctx)
	//Generate N signed pre-certificates
	issuer := Generate_Issuer(ctx.CA_private_config.Signer)
	// generate host
	host := "www.example.com"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(ctx, ctx.CA_private_config.Cert_per_period, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.PrivateKey, 0)
	fmt.Println(len(certs))
	//Send the pre-certificates to the log
	// iterate over certs
	for i := 0; i < len(certs); i++ {
		//store in current cert pool
		ctx.CurrentCertificatePool.AddCert(certs[i])
		fmt.Println(certs[i].SubjectKeyId)
		Send_Signed_PreCert_To_Loggers(ctx, certs[i], ctx.CA_private_config.Loggerlist)
	}
	fmt.Println("CA Finished Sending Pre-Certs to Loggers")
	f1 := func() {
		// want to see if the STHs and POIs are updated
		var certlist []x509.Certificate
		certlist = ctx.CurrentCertificatePool.GetCerts()
		for i := 0; i < len(certlist); i++ {
			//var ctngexts []CTngExtension
			//ctngexts = GetCTngExtensions(&certlist[i])
			//fmt.Println("CTng Extension for Cert", i, "is", ctngexts)
		}
		// get current period
		period := GetCurrentPeriod()
		// convert string to int
		periodnum, err := strconv.Atoi(period)
		if err != nil {
		}
		// add 1 to current period
		periodnum = periodnum + 1
		// convert int to string
		period = strconv.Itoa(periodnum)
		rev := Generate_Revocation(ctx, period, 0)
		fake_rev := Generate_Revocation(ctx, period, 1)
		ctx.REV_storage[period] = rev
		ctx.REV_storage[fake_rev.Period] = fake_rev
		fmt.Println("CA Finished Generating Revocation for next period")
		ctx.SaveToStorage()
	}
	time.AfterFunc(time.Duration(ctx.CA_public_config.MMD-20)*time.Second, f1)
}

// Our CA does not create certificate by requests
// The purpose of the CA is for testing purposes only
func StartCA(c *CAContext) {
	currentsecond := GerCurrentSecond()
	// convert string to int
	second, err := strconv.Atoi(currentsecond)
	if err != nil {
	}
	// if current second is not 0, wait till the next minute
	if second != 0 {
		fmt.Println("CA will start", 60-second+1, " seconds later.")
		time.Sleep(time.Duration(60-second+1) * time.Second)
	}
	// Initialize CA context
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// Start HTTP server loop on the main thread
	go PeriodicTask(c)
	handleCARequests(c)
}
