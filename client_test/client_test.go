package client_test

import (
	"CTng/CA"
	"CTng/Gen"
	"CTng/Logger"
	"CTng/crypto"
	"CTng/gossip"
	"CTng/monitor"
	"CTng/util"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"
	"time"
)

// global network settings
var num_ca int = 3
var num_logger int = 3
var num_gossiper int = 4
var num_monitor int = 4
var Threshold int = 2
var num_cert int = 7
var MMD int = 60
var MRD int = 60
var config_path string = ""

// CA specific settings
var issuers []pkix.Name
var host = "localhost"
var isCA = false
var validFor = time.Hour * 24 * 365

// the following variables are used to initialize the context
var ctx_ca []*CA.CAContext
var ctx_logger []*Logger.LoggerContext
var ctx_gossiper []*gossip.GossiperContext
var ctx_monitor []*monitor.MonitorContext

// the following variables are used to print out the logs
// Precent Pool: prior to the cert being logged
var Precert_pool [][]*x509.Certificate
var SignedCertPool [][]x509.Certificate
var PrivPool [][]*rsa.PrivateKey

// Cert Pool: after the cert is logged
var STHs map[gossip.Gossip_ID]gossip.Gossip_object
var STHs_fake map[gossip.Gossip_ID]gossip.Gossip_object
var REVs map[gossip.Gossip_ID]gossip.Gossip_object
var REVs_fake map[gossip.Gossip_ID]gossip.Gossip_object

//Monitor Storage
var STH_FULL [][]gossip.Gossip_object
var REV_FULL [][]gossip.Gossip_object
var ACC_FULL [][]gossip.Gossip_object
var CON_FULL [][]gossip.Gossip_object
var NUM [][]gossip.NUM
var NUM_FULL []gossip.NUM_FULL
var Update_FULL []monitor.ClientUpdate

func test_gen(t *testing.T) {
	Gen.Generateall(num_gossiper, Threshold, num_logger, num_ca, num_cert, MMD, MRD, config_path)
}

func Test_init_variables(t *testing.T) {
	Precert_pool = make([][]*x509.Certificate, num_ca)
	STHs = make(map[gossip.Gossip_ID]gossip.Gossip_object)
	STHs_fake = make(map[gossip.Gossip_ID]gossip.Gossip_object)
	REVs = make(map[gossip.Gossip_ID]gossip.Gossip_object)
	REVs_fake = make(map[gossip.Gossip_ID]gossip.Gossip_object)
	SignedCertPool = make([][]x509.Certificate, 4*num_cert)
	STH_FULL = make([][]gossip.Gossip_object, 4*num_logger)
	REV_FULL = make([][]gossip.Gossip_object, 4*num_ca)
	ACC_FULL = make([][]gossip.Gossip_object, 4*(num_logger+num_ca))
	CON_FULL = make([][]gossip.Gossip_object, 4*(num_logger+num_ca))
	NUM = make([][]gossip.NUM, 4*(num_logger+num_ca))
	NUM_FULL = make([]gossip.NUM_FULL, 4*(num_logger+num_ca))
	Update_FULL = make([]monitor.ClientUpdate, 4*(num_logger+num_ca))
	PrivPool = make([][]*rsa.PrivateKey, num_ca)
}

func Test_Context_Init(t *testing.T) {
	for i := 0; i < num_ca; i++ {
		ctx_ca = append(ctx_ca, Gen.InitializeOneEntity("CA", fmt.Sprint(i+1)).(*CA.CAContext))
		issuers = append(issuers, CA.Generate_Issuer("CA "+fmt.Sprint(i+1)))
	}
	for i := 0; i < num_logger; i++ {
		ctx_logger = append(ctx_logger, Gen.InitializeOneEntity("Logger", fmt.Sprint(i+1)).(*Logger.LoggerContext))
	}
	for i := 0; i < num_monitor; i++ {
		ctx_monitor = append(ctx_monitor, Gen.InitializeOneEntity("Monitor", fmt.Sprint(i+1)).(*monitor.MonitorContext))
	}
	for i := 0; i < num_gossiper; i++ {
		ctx_gossiper = append(ctx_gossiper, Gen.InitializeOneEntity("Gossiper", fmt.Sprint(i+1)).(*gossip.GossiperContext))
	}
	fmt.Println("CA URLs are shown below:")
	fmt.Println(ctx_ca[0].CA_crypto_config.SelfID, ctx_ca[1].CA_crypto_config.SelfID, ctx_ca[2].CA_crypto_config.SelfID)
	fmt.Println("Logger URLs are shown below:")
	fmt.Println(ctx_logger[0].Logger_crypto_config.SelfID, ctx_logger[1].Logger_crypto_config.SelfID, ctx_logger[2].Logger_crypto_config.SelfID)
	fmt.Println("Monitor URLs are shown below:")
	fmt.Println(ctx_monitor[0].Config.Crypto.SelfID, ctx_monitor[1].Config.Crypto.SelfID, ctx_monitor[2].Config.Crypto.SelfID, ctx_monitor[3].Config.Crypto.SelfID)
	fmt.Println("Gossiper URLs are shown below:")
	fmt.Println(ctx_gossiper[0].Config.Crypto.SelfID, ctx_gossiper[1].Config.Crypto.SelfID, ctx_gossiper[2].Config.Crypto.SelfID, ctx_gossiper[3].Config.Crypto.SelfID)
	fmt.Println("________________________________Context_Init_Successful________________________________")
}

func ca_logger_setup(Period int) {
	fmt.Println("________________________________CA_Logger_Running_at_Period ", Period, "________________________________")
	for i := 0; i < num_ca; i++ {
		ncp, privlist := CA.Generate_N_Signed_PreCert_with_priv(ctx_ca[i], num_cert, host, validFor, isCA, issuers[i], ctx_ca[i].Rootcert, false, &ctx_ca[i].CA_crypto_config.RSAPrivateKey, num_cert*i+21*(Period))

		//append the values to PrivPool
		PrivPool[i] = append(PrivPool[i], privlist...)
		Precert_pool[i] = append(Precert_pool[i], ncp...)
		for j := 0; j < len(Precert_pool[i]); j++ {
			ctx_ca[i].CurrentCertificatePool.AddCert(Precert_pool[i][j])
		}
		Precert_pool[i] = nil
	}
	fmt.Println("PreCert_Pool_Length: ", ctx_ca[0].CurrentCertificatePool.GetLength(), ctx_ca[1].CurrentCertificatePool.GetLength(), ctx_ca[2].CurrentCertificatePool.GetLength())
	fmt.Println("Sequence_Number for each CA starts at: ", CA.GetSequenceNumberfromCert(ctx_ca[0].CurrentCertificatePool.GetCertList()[0]), CA.GetSequenceNumberfromCert(ctx_ca[1].CurrentCertificatePool.GetCertList()[0]), CA.GetSequenceNumberfromCert(ctx_ca[2].CurrentCertificatePool.GetCertList()[0]))
	fmt.Println(ctx_ca[1].CurrentCertificatePool.GetCertList()[3].PublicKey)
	fmt.Println(PrivPool[1][3].PublicKey)
	//fmt.Println("________________________________CA_Pre_Cert_Gen_Successful________________________________")
	//cert 1 from all CAs logged by logger 1
	//cert 2 from all CAs logged by logger 2
	//cert 3 from all CAs logged by logger 3
	//cert 4 from all CAs logged by logger 1 and logger 2
	//cert 5 from all CAs logged by logger 1 and logger 3
	//cert 6 from all CAs logged by logger 2 and logger 3
	//cert 7 from all CAs logged by logger 1, logger 2 and logger 3
	for i := 0; i < num_ca; i++ {
		// Logger 1 logs cert 1,4,5,7 from all CAs
		ctx_logger[0].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[0])
		ctx_logger[0].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[3])
		ctx_logger[0].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[5])
		ctx_logger[0].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[6])
		// Logger 2 logs cert 2,4,6,7 from all CAs
		ctx_logger[1].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[1])
		ctx_logger[1].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[3])
		ctx_logger[1].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[4])
		ctx_logger[1].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[6])
		// Logger 3 logs cert 3,5,6,7 from all CAs
		ctx_logger[2].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[2])
		ctx_logger[2].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[4])
		ctx_logger[2].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[5])
		ctx_logger[2].CurrentPrecertPool.AddCert(ctx_ca[i].CurrentCertificatePool.GetCertList()[6])
	}
	fmt.Println("Number of pre-cert logged by each logger: ", ctx_logger[0].CurrentPrecertPool.GetLength(), ctx_logger[1].CurrentPrecertPool.GetLength(), ctx_logger[2].CurrentPrecertPool.GetLength())
	//fmt.Println("________________________________Logger_Add_precert_successful________________________________")
	for i := 0; i < num_logger; i++ {
		STH, _, MerkleNodes := Logger.BuildMerkleTreeFromCerts(ctx_logger[i].CurrentPrecertPool.GetCerts(), *ctx_logger[i], Period)
		ID := STH.GetID()
		STHs[ID] = STH
		// intentionally ignore one of the Certs
		cert_pool_l := ctx_logger[i].CurrentPrecertPool.GetCerts()
		// omit the last cert
		cert_pool_l = cert_pool_l[:len(cert_pool_l)-1]
		// now we have the fake STH
		FakeSTH, _, _ := Logger.BuildMerkleTreeFromCerts(cert_pool_l, *ctx_logger[i], Period)
		ID = FakeSTH.GetID()
		STHs_fake[ID] = FakeSTH
		for j := 0; j < len(MerkleNodes); j++ {
			CAPOI := CA.ProofOfInclusion{
				SiblingHashes: MerkleNodes[j].Poi.SiblingHashes,
				NeighborHash:  MerkleNodes[j].Poi.NeighborHash,
			}
			extension := CA.CTngExtension{
				STH: STH,
				POI: CAPOI,
			}
			switch MerkleNodes[j].Issuer {
			case "localhost:9100":
				//fmt.Println("MerkleNode Issuer: ",MerkleNodes[j].Issuer)
				target_cert := ctx_ca[0].CurrentCertificatePool.GetCertBySubjectKeyID(string(MerkleNodes[j].SubjectKeyId))
				target_cert = CA.AddCTngExtension(target_cert, extension)
				ctx_ca[0].CurrentCertificatePool.UpdateCertBySubjectKeyID(string(MerkleNodes[j].SubjectKeyId), target_cert)
			case "localhost:9101":
				//fmt.Println("MerkleNode Issuer: ",MerkleNodes[j].Issuer)
				target_cert := ctx_ca[1].CurrentCertificatePool.GetCertBySubjectKeyID(string(MerkleNodes[j].SubjectKeyId))
				target_cert = CA.AddCTngExtension(target_cert, extension)
				ctx_ca[1].CurrentCertificatePool.UpdateCertBySubjectKeyID(string(MerkleNodes[j].SubjectKeyId), target_cert)
			case "localhost:9102":
				//fmt.Println("MerkleNode Issuer: ",MerkleNodes[j].Issuer)
				target_cert := ctx_ca[2].CurrentCertificatePool.GetCertBySubjectKeyID(string(MerkleNodes[j].SubjectKeyId))
				target_cert = CA.AddCTngExtension(target_cert, extension)
				ctx_ca[2].CurrentCertificatePool.UpdateCertBySubjectKeyID(string(MerkleNodes[j].SubjectKeyId), target_cert)
			}
		}
	}
	fmt.Println("Number of CTng extensions on cert 1 from each CA: ", CA.GetCTngExtensionCount(ctx_ca[0].CurrentCertificatePool.GetCertList()[0]), CA.GetCTngExtensionCount(ctx_ca[1].CurrentCertificatePool.GetCertList()[0]), CA.GetCTngExtensionCount(ctx_ca[2].CurrentCertificatePool.GetCertList()[0]))
	fmt.Println("Number of CTng extensions on cert 4 from each CA: ", CA.GetCTngExtensionCount(ctx_ca[0].CurrentCertificatePool.GetCertList()[3]), CA.GetCTngExtensionCount(ctx_ca[1].CurrentCertificatePool.GetCertList()[3]), CA.GetCTngExtensionCount(ctx_ca[2].CurrentCertificatePool.GetCertList()[3]))
	fmt.Println("Number of CTng extensions on cert 7 from each CA: ", CA.GetCTngExtensionCount(ctx_ca[0].CurrentCertificatePool.GetCertList()[6]), CA.GetCTngExtensionCount(ctx_ca[1].CurrentCertificatePool.GetCertList()[6]), CA.GetCTngExtensionCount(ctx_ca[2].CurrentCertificatePool.GetCertList()[6]))
	//fmt.Println("________________________________CTng_Extension_Successful________________________________")
	for i := 0; i < num_ca; i++ {
		signed_certs := CA.SignAllCerts(ctx_ca[i])
		SignedCertPool[i] = append(SignedCertPool[i], signed_certs...)
		if Period == 3 {
			ctx_ca[i].CRV.Revoke(28)
		}
		revocation := CA.Generate_Revocation(ctx_ca[i], fmt.Sprint(Period), 0)
		REVs[revocation.GetID()] = revocation
		revocation_fake := CA.Generate_Revocation(ctx_ca[i], fmt.Sprint(Period), 1)
		REVs_fake[revocation_fake.GetID()] = revocation_fake
	}
	fmt.Println("Number of signed certs from each CA: ", len(SignedCertPool[0]), len(SignedCertPool[1]), len(SignedCertPool[2]))
	fmt.Println("Number of STHs and Fake STHs: ", len(STHs), len(STHs_fake))
	fmt.Println("Number of REV and Fake REV: ", len(REVs), len(REVs_fake))
	fmt.Println("CRV: ", ctx_ca[0].CRV.CRV_current, ctx_ca[1].CRV.CRV_current, ctx_ca[2].CRV.CRV_current)
	// clean up ctx_ca_current_cert_pool and ctx_logger_current_precert_pool
	for i := 0; i < num_ca; i++ {
		ctx_ca[i].CurrentCertificatePool = CA.NewCertPool()
	}
	for i := 0; i < num_logger; i++ {
		ctx_logger[i].CurrentPrecertPool = CA.NewCertPool()
	}
}

func GID_setup(Period int) ([]gossip.Gossip_ID, []gossip.Gossip_ID) {
	Gossip_ID1 := gossip.Gossip_ID{
		Period:     fmt.Sprint(Period),
		Type:       gossip.STH,
		Entity_URL: "localhost:9000",
	}
	Gossip_ID2 := gossip.Gossip_ID{
		Period:     fmt.Sprint(Period),
		Type:       gossip.STH,
		Entity_URL: "localhost:9001",
	}
	Gossip_ID3 := gossip.Gossip_ID{
		Period:     fmt.Sprint(Period),
		Type:       gossip.STH,
		Entity_URL: "localhost:9002",
	}
	Gossip_ID4 := gossip.Gossip_ID{
		Period:     fmt.Sprint(Period),
		Type:       gossip.REV,
		Entity_URL: "localhost:9100",
	}
	Gossip_ID5 := gossip.Gossip_ID{
		Period:     fmt.Sprint(Period),
		Type:       gossip.REV,
		Entity_URL: "localhost:9101",
	}
	Gossip_ID6 := gossip.Gossip_ID{
		Period:     fmt.Sprint(Period),
		Type:       gossip.REV,
		Entity_URL: "localhost:9102",
	}
	GID_list_STH := []gossip.Gossip_ID{Gossip_ID1, Gossip_ID2, Gossip_ID3}
	GID_list_REV := []gossip.Gossip_ID{Gossip_ID4, Gossip_ID5, Gossip_ID6}
	return GID_list_STH, GID_list_REV
}

func generate_TSS_FULL(Period int, object gossip.Gossip_object, SrcType string) gossip.Gossip_object {
	var TargetType string
	switch SrcType {
	case gossip.STH:
		TargetType = gossip.STH_FULL
	case gossip.REV:
		TargetType = gossip.REV_FULL
	case gossip.ACC:
		TargetType = gossip.ACC_FULL
	case gossip.CON:
		TargetType = gossip.CON_FULL
	}
	partial_sig_list := make([]crypto.SigFragment, Threshold)
	signermap := make(map[int]string)
	for i := 0; i < Threshold; i++ {
		partial_sig, _ := ctx_gossiper[i].Config.Crypto.ThresholdSign(object.Payload[0] + object.Payload[1] + object.Payload[2])
		partial_sig_list[i] = partial_sig
		signermap[i] = ctx_gossiper[i].Config.Crypto.SelfID.String()
	}
	//fmt.Println("Partial sig list: ",partial_sig_list)
	sig, _ := ctx_gossiper[0].Config.Crypto.ThresholdAggregate(partial_sig_list)
	sigtring, _ := sig.String()
	TSS_FULL := gossip.Gossip_object{
		Application:   "CTng",
		Type:          TargetType,
		Period:        fmt.Sprint(Period),
		Signer:        "",
		Signers:       signermap,
		Timestamp:     gossip.GetCurrentTimestamp(),
		Signature:     [2]string{sigtring, ""},
		Crypto_Scheme: "BLS",
		Payload:       object.Payload,
	}
	return TSS_FULL
}

func generateCON(Period int, obj gossip.Gossip_object, dup gossip.Gossip_object) gossip.Gossip_object {
	D2_POM := gossip.Gossip_object{
		Application: obj.Application,
		Type:        gossip.CON,
		Period:      fmt.Sprint(Period),
		Signer:      "",
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{obj.Signature[0], dup.Signature[0]},
		Payload:     [3]string{obj.Signer, obj.Payload[0] + obj.Payload[1] + obj.Payload[2], dup.Payload[0] + dup.Payload[1] + dup.Payload[2]},
	}
	return D2_POM
}

func generateACC(Period int, Entity_URL string) gossip.Gossip_object {
	ACC := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.ACC,
		Period:      fmt.Sprint(Period),
		Signer:      "",
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{"", ""},
		Payload:     [3]string{Entity_URL, "", ""},
	}
	return ACC
}

func Test_Create_Data_Folders(t *testing.T) {
	// create a folder named ClientData if not exist
	if _, err := os.Stat("ClientData"); os.IsNotExist(err) {
		os.Mkdir("ClientData", 0777)
	}
	// create 4 folders under ClientData
	for i := 0; i < 4; i++ {
		// folder name is Period + fmt.Sprint(i)
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(i)); os.IsNotExist(err) {
			os.Mkdir("ClientData/Period "+fmt.Sprint(i), 0777)
		}
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(i) + "/FromWebserver"); os.IsNotExist(err) {
			os.Mkdir("ClientData/Period "+fmt.Sprint(i)+"/FromWebserver", 0777)
		}
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(i) + "/FromMonitor"); os.IsNotExist(err) {
			os.Mkdir("ClientData/Period "+fmt.Sprint(i)+"/FromMonitor", 0777)
		}
	}
}

func saveCertificateToDisk(certBytes []byte, filePath string) {
	certOut, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", filePath, err)
	}
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s: %v", filePath, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", filePath, err)
	}
}

func saveKeyToDisk(privKey *rsa.PrivateKey, filePath string) {
	keyOut, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", filePath, err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s: %v", filePath, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", filePath, err)
	}
}

func Test_CA_Logger(t *testing.T) {
	// this part produces signed certs with CTng extensions
	ca_logger_setup(0)
	ca_logger_setup(1)
	ca_logger_setup(2)
	ca_logger_setup(3)
	// start write data to /ClientData/Period 0/FromWebserver
	for i := 0; i < 3; i++ {
		for j := 0; j < 7; j++ {
			// write the certificate to /ClientData/Period 0/FromWebserver
			certsaved := SignedCertPool[i][j]
			keysaved := PrivPool[i][j]
			filename := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".crt"
			filename2 := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".key"
			derbytes := certsaved.Raw
			saveCertificateToDisk(derbytes, "ClientData/Period 0/FromWebserver/"+filename)
			saveKeyToDisk(keysaved, "ClientData/Period 0/FromWebserver/"+filename2)
		}
		for j := 7; j < 14; j++ {
			// write the certificate to /ClientData/Period 0/FromWebserver
			certsaved := SignedCertPool[i][j]
			keysaved := PrivPool[i][j]
			filename := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".crt"
			filename2 := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".key"
			derbytes := certsaved.Raw
			saveCertificateToDisk(derbytes, "ClientData/Period 1/FromWebserver/"+filename)
			saveKeyToDisk(keysaved, "ClientData/Period 1/FromWebserver/"+filename2)
		}
		for j := 14; j < 21; j++ {
			// write the certificate to /ClientData/Period 0/FromWebserver
			certsaved := SignedCertPool[i][j]
			keysaved := PrivPool[i][j]
			filename := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".crt"
			filename2 := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".key"
			derbytes := certsaved.Raw
			saveCertificateToDisk(derbytes, "ClientData/Period 2/FromWebserver/"+filename)
			saveKeyToDisk(keysaved, "ClientData/Period 2/FromWebserver/"+filename2)
		}
		for j := 21; j < 28; j++ {
			// write the certificate to /ClientData/Period 0/FromWebserver
			certsaved := SignedCertPool[i][j]
			keysaved := PrivPool[i][j]
			filename := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".crt"
			filename2 := "CA " + fmt.Sprint(i) + "_" + certsaved.Subject.CommonName + "_" + fmt.Sprint(CA.GetSequenceNumberfromCert(&certsaved)) + ".key"
			derbytes := certsaved.Raw
			saveCertificateToDisk(derbytes, "ClientData/Period 3/FromWebserver/"+filename)
			saveKeyToDisk(keysaved, "ClientData/Period 3/FromWebserver/"+filename2)
		}
	}
}

func writeall(period int, Num_STH_FULL int, Num_REV_FULL int, Num_ACC_FULL int, Num_CON_FULL int) {
	var filename string
	// write the monitor data to the path ClientData/Period 0/FromMonitor, create file if not exist
	// write STH_FULL
	/*
		filename := "STH_FULL_" + fmt.Sprint(Num_STH_FULL) + ".json"
		//create file if not exist
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename); os.IsNotExist(err) {
			os.Create("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename)
		}
		// write to file
		util.WriteData("ClientData/Period "+fmt.Sprint(period)+"/FromMonitor/"+filename, STH_FULL[period])
		// write REV_FULL
		filename = "REV_FULL_" + fmt.Sprint(Num_REV_FULL) + ".json"
		//create file if not exist
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename); os.IsNotExist(err) {
			os.Create("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename)
		}
		// write to file
		util.WriteData("ClientData/Period "+fmt.Sprint(period)+"/FromMonitor/"+filename, REV_FULL[period])
		// write ACC_FULL
		filename = "ACC_FULL_" + fmt.Sprint(Num_ACC_FULL) + ".json"
		//create file if not exist
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename); os.IsNotExist(err) {
			os.Create("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename)
		}
		// write to file
		util.WriteData("ClientData/Period "+fmt.Sprint(period)+"/FromMonitor/"+filename, ACC_FULL[period])
		// write CON_FULL
		filename = "CON_FULL_" + fmt.Sprint(Num_CON_FULL) + ".json"
		//create file if not exist
		if _, err := os.Stat("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename); os.IsNotExist(err) {
			os.Create("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename)
		}
		// write to file
		util.WriteData("ClientData/Period "+fmt.Sprint(period)+"/FromMonitor/"+filename, CON_FULL[period])*/
	filename = "ClientUpdate_at_Period " + fmt.Sprint(period) + ".json"
	//create file if not exist
	if _, err := os.Stat("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename); os.IsNotExist(err) {
		os.Create("ClientData/Period " + fmt.Sprint(period) + "/FromMonitor/" + filename)
	}
	// write to file
	util.WriteData("ClientData/Period "+fmt.Sprint(period)+"/FromMonitor/"+filename, Update_FULL[period])
}

func prep_update(period int) {
	for i := 0; i < num_monitor; i++ {
		num := gossip.NUM{
			NUM_ACC_FULL:   strconv.Itoa(len(ACC_FULL[period])),
			NUM_CON_FULL:   strconv.Itoa(len(CON_FULL[period])),
			Period:         strconv.Itoa(period),
			Crypto_Scheme:  "rsa",
			Signer_Monitor: ctx_monitor[i].Config.Signer,
		}
		sig, _ := ctx_monitor[i].Config.Crypto.Sign([]byte(num.NUM_ACC_FULL + num.NUM_CON_FULL + num.Period + num.Signer_Monitor))
		sigstring := sig.String()
		num.Signature = sigstring
		NUM[period] = append(NUM[period], num)
	}
	if period == 2 {
		num_fake := gossip.NUM{
			NUM_ACC_FULL:   strconv.Itoa(len(ACC_FULL[period])),
			NUM_CON_FULL:   strconv.Itoa(len(CON_FULL[period]) - 1),
			Period:         strconv.Itoa(period),
			Crypto_Scheme:  "rsa",
			Signer_Monitor: ctx_monitor[2].Config.Signer,
		}
		sig, _ := ctx_monitor[2].Config.Crypto.Sign([]byte(num_fake.NUM_ACC_FULL + num_fake.NUM_CON_FULL + num_fake.Period + num_fake.Signer_Monitor))
		sigstring := sig.String()
		num_fake.Signature = sigstring
		NUM[period][2] = num_fake
	}
	var num_full gossip.NUM_FULL
	if period > 0 {
		var num_frag_list []*gossip.NUM_FRAG
		for i := 1; i < Threshold+1; i++ {
			num_frag_list = append(num_frag_list, gossip.Generate_NUM_FRAG(&NUM[period-1][i], ctx_gossiper[i].Config.Crypto))
		}
		num_full = *gossip.Generate_NUM_FULL(num_frag_list, ctx_gossiper[0].Config.Crypto)
	}
	NUM_FULL[period] = num_full
	var num_full_for_update gossip.NUM_FULL
	if period == 0 {
		num_full_for_update = gossip.NUM_FULL{}
		// Initialize `Signers` field so that it is not null in json encoding
		num_full_for_update.Signers = map[int]string{}
	} else {
		num_full_for_update = NUM_FULL[period]
	}
	Update_FULL[period] = monitor.ClientUpdate{
		STHs:      STH_FULL[period],
		REVs:      REV_FULL[period],
		ACCs:      ACC_FULL[period],
		CONs:      CON_FULL[period],
		MonitorID: ctx_monitor[2].Config.Signer,
		NUM:       NUM[period][2],
		NUM_FULL:  num_full_for_update,
		Period:    fmt.Sprint(period),
	}
}
func Test_MG_Period0(t *testing.T) {
	// period 0: all loggers and CAs are behaving correctly
	// should have 3 STH FULL, 3 REV FULL, 0 ACC FULL and 0 CON FULL
	GID_L, GID_CA := GID_setup(0)
	for i := 0; i < num_logger; i++ {
		STH_0 := generate_TSS_FULL(0, STHs[GID_L[i]], gossip.STH)
		STH_FULL[0] = append(STH_FULL[0], STH_0)
	}
	for i := 0; i < num_ca; i++ {
		//fmt.Println(REVs[GID_CA[i]].Payload)
		REV_0 := generate_TSS_FULL(0, REVs[GID_CA[i]], gossip.REV)
		REV_FULL[0] = append(REV_FULL[0], REV_0)
	}

	// These need to be initialized to zero values, otherwise the JSON encoding will be null
	ACC_FULL[0] = []gossip.Gossip_object{}
	CON_FULL[0] = []gossip.Gossip_object{}

	prep_update(0)
	// write all the data to the path ClientData/Period 0/FromMonitor
	writeall(0, 3, 3, 0, 0)
}

func Test_MG_Period1(t *testing.T) {
	// period 1: all ca are behaving correctly, 1 logger is behaving correctly, 1 is not responding, 1 is split-world
	// should have 1 STH FULL, 3 REV FULL, 1 ACC FULL and 1 CON FULL
	GID_L, GID_CA := GID_setup(1)
	STH_FULL[1] = append(STH_FULL[1], generate_TSS_FULL(1, STHs[GID_L[0]], gossip.STH))
	ACC_FULL[1] = append(ACC_FULL[1], generate_TSS_FULL(1, generateACC(1, ctx_logger[1].Logger_private_config.Signer), gossip.STH))
	CON_FULL[1] = append(CON_FULL[1], generate_TSS_FULL(1, generateCON(1, STHs[GID_L[2]], STHs_fake[GID_L[2]]), gossip.STH))
	for i := 0; i < num_ca; i++ {
		REV_FULL[1] = append(REV_FULL[1], generate_TSS_FULL(1, REVs[GID_CA[i]], gossip.REV))
	}
	prep_update(1)
	// write all the data to the path ClientData/Period 1/FromMonitor
	writeall(1, 1, 3, 1, 1)
}

func Test_MG_Period2(t *testing.T) {
	// period 3: all loggers are behaving correctly, 1 ca is behaving correctly, 1 is not responding, 1 is split-world, 1 logger is split-world, 1 monitor is protecting the split-world logger
	GID_L, GID_CA := GID_setup(2)
	STH_FULL[2] = append(STH_FULL[2], generate_TSS_FULL(2, STHs[GID_L[1]], gossip.STH))
	REV_FULL[2] = append(REV_FULL[2], generate_TSS_FULL(2, REVs[GID_CA[0]], gossip.REV))
	ACC_FULL[2] = append(ACC_FULL[2], generate_TSS_FULL(2, generateACC(2, ctx_ca[2].CA_private_config.Signer), gossip.REV))
	CON_FULL[2] = append(CON_FULL[2], generate_TSS_FULL(2, generateCON(2, REVs[GID_CA[0]], REVs_fake[GID_CA[0]]), gossip.REV))
	CON_FULL[2] = append(CON_FULL[2], generate_TSS_FULL(2, generateCON(2, STHs[GID_L[0]], STHs_fake[GID_L[0]]), gossip.STH))
	prep_update(2)
	writeall(2, 1, 1, 1, 1)
}

func Test_MG_Period3(t *testing.T) {
	// period 4: all loggers and CAs are behaving correctly
	// should have 3 STH FULL, 3 REV FULL, 0 ACC FULL and 0 CON FULL
	GID_L, GID_CA := GID_setup(3)
	for i := 0; i < num_logger-1; i++ {
		STH_3 := generate_TSS_FULL(3, STHs[GID_L[i]], gossip.STH)
		STH_FULL[3] = append(STH_FULL[3], STH_3)
	}
	for i := 0; i < num_ca-1; i++ {
		//fmt.Println(REVs[GID_CA[i]].Payload)
		REV_3 := generate_TSS_FULL(3, REVs[GID_CA[i]], gossip.REV)
		REV_FULL[3] = append(REV_FULL[3], REV_3)
	}
	prep_update(3)
	// write all the data to the path ClientData/Period 3/FromMonitor
	writeall(3, 2, 2, 0, 0)
}
