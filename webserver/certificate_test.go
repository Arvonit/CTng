package webserver

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"

	//"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"testing"
)

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

func testCreateCA(t *testing.T) {
	// Create a new certificate authority
	ca := CreateCA("CTng Certificate Authority")

	// Save CA root certificate to disk
	saveCertificateToDisk(ca.RootCertificateSigned, "test/ca.crt")
	log.Println("Wrote cert to disk")

	// Save CA private key to disk
	saveKeyToDisk(ca.PrivateKey, "test/ca.key")
	log.Println("Wrote priv key to disk")
}

func testCreateCertificate(t *testing.T) {
	// Read CA root certificate from disk
	ca := ReadCAFromDisk("test/ca.crt", "test/ca.key")
	// ca := CreateCA("CTng Certificate Authority")

	// Create a private key for our certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate cert private key: %v", err)
	}

	// Create a new certificate
	_, certBytes := ca.CreateCertificate("CTng Normal Certificate", &certPrivKey.PublicKey)

	// Save the certificate to disk
	saveCertificateToDisk(certBytes, "test/normal.crt")
	log.Println("Wrote cert to disk")

	// Save certificate's private key to disk
	saveKeyToDisk(certPrivKey, "test/normal.key")
	log.Println("Wrote priv key to disk")
}

func testCreatePOMCertificate(t *testing.T) {
	// Create a new "malicious" CA
	ca := CreateCA("Evil Certificate Authority")

	// Create a private key for the certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate cert private key: %v", err)
	}

	// Create a new certificate
	_, certBytes := ca.CreateCertificate("CTng POM Certificate", &certPrivKey.PublicKey)

	// Save the certificate to disk
	saveCertificateToDisk(certBytes, "test/pom.crt")
	log.Println("Wrote cert to disk")

	// Save certificate's private key to disk
	saveKeyToDisk(certPrivKey, "test/pom.key")
	log.Println("Wrote priv key to disk")
}

func testCreateRevokedCertificate(t *testing.T) {
	// Read CA root certificate from disk
	ca := ReadCAFromDisk("test/ca.crt", "test/ca.key")

	// Create a private key for our certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate cert private key: %v", err)
	}

	// Create a new certificate
	_, certBytes := ca.CreateCertificate("CTng Revoked Certificate", &certPrivKey.PublicKey)

	// Save the certificate to disk
	saveCertificateToDisk(certBytes, "test/revoked.crt")
	log.Println("Wrote cert to disk")

	// Save certificate's private key to disk
	saveKeyToDisk(certPrivKey, "test/revoked.key")
	log.Println("Wrote priv key to disk")
}

func readCertificateFromDisk(filePath string) ([]byte, error) {
	certFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	pemFileInfo, err := certFile.Stat()
	if err != nil {
		return nil, err
	}

	var certBytes []byte = make([]byte, pemFileInfo.Size())
	_, err = certFile.Read(certBytes)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM data")
	}

	return block.Bytes, nil
}

func readKeyFromDisk(filePath string) (*rsa.PrivateKey, error) {
	keyFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	pemFileInfo, err := keyFile.Stat()
	if err != nil {
		return nil, err
	}

	var keyBytes []byte = make([]byte, pemFileInfo.Size())
	_, err = keyFile.Read(keyBytes)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return privKey, nil
}

func testLoadkeyandcert(*testing.T) {
	certpath := "../client_test/ClientData/Period 0/FromWebserver/CA 0_Testing Dummy 1_2.crt"
	keypath := "../client_test/ClientData/Period 0/FromWebserver/Testing Dummy 2_private.key"
	cert, err := readCertificateFromDisk(certpath)
	if err != nil {
		log.Fatalf("Failed to read certificate from disk: %v", err)
	}
	key, err := readKeyFromDisk(keypath)
	if err != nil {
		log.Fatalf("Failed to read key from disk: %v", err)
	}

	//fmt.Println(cert)
	//fmt.Println(key)
	loadInvalidCertificate(cert, x509.MarshalPKCS1PrivateKey(key))
	cert_new, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	fmt.Println(cert_new.Subject.CommonName)
	//fmt.Println(cert_new.CRLDistributionPoints)
	pub := cert_new.PublicKey.(*rsa.PublicKey)
	pub2 := key.PublicKey
	fmt.Println(pub.N)
	fmt.Println(pub2.N)
	fmt.Println(pub.N.Cmp(pub2.N) == 0 && pub.E == pub2.E)

	msg := []byte("Hello World")
	hash := sha256.Sum256(msg)
	hashmsg := hash[:]
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashmsg)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashmsg, sig)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}
	fmt.Println("Verified")

}

func loadInvalidCertificate(certbytes []byte, keybytes []byte) (*tls.Certificate, error) {
	invalidCert, err := tls.X509KeyPair(certbytes, keybytes)
	if err != nil {
		return nil, err
	}
	return &invalidCert, nil
}

func TestLoadvalidcert(*testing.T) {
	certpath := "../client_test/ClientData/Period 0/FromWebserver/CA 0_Testing Dummy 1_2.crt"
	keypath := "../client_test/ClientData/Period 0/FromWebserver/Testing Dummy 2_private.key"
	cert, _ := tls.LoadX509KeyPair(certpath, keypath)
	fmt.Println(cert)
}
