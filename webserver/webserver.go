package webserver

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

// Runs a HTTPS web server that serves a different CTng certificate depending on the port.
//
// There are a total of 84 certificates — 21 for each of the four periods. Therefore, there is
// a web server running on ports 8000 to 8083.
func Start() {

	certs := getCTngCertificates()
	numCerts := len(certs)
	// fmt.Println(numCerts)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to the CTng web server!"))
	})

	var servers []http.Server
	for i := 0; i < numCerts; i++ {
		servers = append(servers, http.Server{
			Addr: fmt.Sprintf("localhost:8%03d", i),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{certs[i]},
			},
			Handler: mux,
		})
	}

	log.Printf("Listening on ports {8000...8%03d}\n", numCerts-1)
	for i := 1; i < numCerts; i++ {
		// fmt.Println(servers[i].Addr)
		s := servers[i]
		go func() {
			if err := s.ListenAndServeTLS("", ""); err != nil {
				log.Fatal(err)
				// fmt.Println(err)
			}
		}()
	}

	// fmt.Println(servers[0].Addr)
	if err := servers[0].ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

// Fetch all CTng Certificates from the client_test folder.
func getCTngCertificates() []tls.Certificate {
	var out []tls.Certificate
	certFiles := []string{}
	folders := []string{
		"./client_test/ClientData/Period 0/FromWebserver",
		"./client_test/ClientData/Period 1/FromWebserver",
		"./client_test/ClientData/Period 2/FromWebserver",
		"./client_test/ClientData/Period 3/FromWebserver",
	}

	for _, folder := range folders {
		filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				panic(err)
			}
			if filepath.Ext(d.Name()) == ".crt" {
				certFiles = append(certFiles, strings.TrimSuffix(path, filepath.Ext(path)))
			}

			return nil
		})
	}

	for _, fileName := range certFiles {
		cert, err := tls.LoadX509KeyPair(fileName+".crt", fileName+".key")
		if err != nil {
			// fmt.Println(fileName)
			// fmt.Println(err)
			panic(err)
		}
		out = append(out, cert)
	}

	return out
}

// Deprecated:
// Run a HTTPS web server that returns a different type of CTng certificate depending on the port:
// 1. A normal, valid certificate on port 8000
// 2. A revoked certificate on port 8001
// 3. A certificate from an entity that has a proof of misbehavior (POM) against them on port 8002
func StartOld() {
	normalCert, revokedCert, pomCert := getCertificates()

	normalMux := http.NewServeMux()
	normalMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This website has a normal certificate."))
	})
	revokedMux := http.NewServeMux()
	revokedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This website has a certificate that has been revoked."))
	})
	pomMux := http.NewServeMux()
	pomMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This website has a certificate from an entity that has a POM against them."))
	})

	normalServer := http.Server{
		Addr: "localhost:8000",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{normalCert},
		},
		Handler: normalMux,
	}
	revokedServer := http.Server{
		Addr: "localhost:8001",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{revokedCert},
		},
		Handler: revokedMux,
	}
	pomServer := http.Server{
		Addr: "localhost:8002",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pomCert},
		},
		Handler: pomMux,
	}

	log.Println("Listening on port 8000, 8001, and 8002")

	go func() {
		if err := normalServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := revokedServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()

	if err := pomServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

// Deprecated:
// Get the certificates to be used by the server
func getCertificates() (tls.Certificate, tls.Certificate, tls.Certificate) {
	normalCert, err := tls.LoadX509KeyPair("webserver/test/normal.crt", "webserver/test/normal.key")
	if err != nil {
		panic(err)
	}
	revokedCert, err := tls.LoadX509KeyPair("webserver/test/revoked.crt", "webserver/test/revoked.key")
	if err != nil {
		panic(err)
	}
	pomCert, err := tls.LoadX509KeyPair("webserver/test/pom.crt", "webserver/test/pom.key")
	if err != nil {
		panic(err)
	}
	return normalCert, revokedCert, pomCert
}
