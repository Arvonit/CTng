package client

import (
	"CTng/gossip"
	"CTng/monitor"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type MonitorData = []gossip.Gossip_object

// Fetch an entity from the given url and parse it as a client update object
func FetchClientUpdate(url string) (monitor.ClientUpdate, error) {
	res, err := fetch(url)
	if err != nil {
		return monitor.ClientUpdate{}, err
	}

	var data monitor.ClientUpdate
	err = json.Unmarshal(res, &data)
	return data, err
}

// Fetch an entity from the given url and parse it as an array of gossip objects
func FetchGossip(url string) (MonitorData, error) {
	res, err := fetch(url)
	if err != nil {
		return MonitorData{}, err
	}

	var data MonitorData
	err = json.Unmarshal(res, &data)
	return data, err
}

// Get the x509 certificate from the given url
func FetchCertificate(url string) (x509.Certificate, error) {
	// CTng certificates, having been created by our own CA, will not pass TLS verification, so we
	// must disable it
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Get(url)
	if err != nil {
		return x509.Certificate{}, err
	}

	// if res.TLS != nil {
	// 	certificates := res.TLS.PeerCertificates
	// 	if len(certificates) > 0 && certificates[0] != nil {
	// 		return *certificates[0], nil
	// 	}
	// }

	// return x509.Certificate{}, nil

	// Make sure website has a certificate
	if res.TLS == nil {
		return x509.Certificate{}, nil
	}

	// Return the first certificate, if it exists
	certificates := res.TLS.PeerCertificates
	if len(certificates) == 0 && certificates[0] != nil {
		return x509.Certificate{}, fmt.Errorf("no certificate")
	}

	return *certificates[0], nil
}

func fetch(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return resBody, err
	}

	if res.StatusCode != http.StatusOK {
		return resBody, fmt.Errorf("server returned status code %v: %v", res.StatusCode, string(resBody))
	}

	return resBody, nil
}
