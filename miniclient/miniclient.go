package miniclient

import (
	"CTng/monitor"
	"CTng/util"
	"fmt"
	"os"
)

func Start() {
	QueryMonitor()
	fmt.Println()
	QueryServer()
}

func QueryMonitor() {
	res, err := FetchClientUpdate("http://localhost:3000/?period=3")
	if err != nil {
		fmt.Printf("client update err: %v\n", err)
		return
	}

	fmt.Printf("monitor id: %v\n", res.MonitorID)
	fmt.Printf("period: %v\n\n", res.Period)
	fmt.Printf("sth: %v\n\n", res.STHs)
	fmt.Printf("rev: %v\n\n", res.REVs)
	fmt.Printf("acc: %v\n\n", res.ACCs)
	fmt.Printf("con: %v\n\n", res.CONs)

	fmt.Printf("num: %v\n\n", res.NUM)
	fmt.Printf("num full: %v\n\n", res.NUM_FULL)

	fmt.Printf("sth root hash:\n%v\n\n", GetRootHash(res.STHs))
	fmt.Printf("rev delta crv: %v\n\n", GetDeltaCRV(res.REVs))
	fmt.Printf("rev srh value: %v\n", GetSRH(res.REVs))
	// fmt.Printf("rev payload: %v\n\n", GetPayload(res.REVs))
	
	SaveClientUpdate(&res)
}

func QueryServer() {
	cert, err := FetchCertificate("https://localhost:8000")
	if err != nil {
		fmt.Printf("normal cert err: %v\n", err)
	} else {
		fmt.Printf("normal cert: %v\n", cert.Subject)
	}

	cert, err = FetchCertificate("https://localhost:8001")
	if err != nil {
		fmt.Printf("revoked cert err: %v\n", err)
	} else {
		fmt.Printf("revoked cert: %v\n", cert.Subject)
	}

	cert, err = FetchCertificate("https://localhost:8002")
	if err != nil {
		fmt.Printf("pom cert err: %v\n", err)
	} else {
		fmt.Printf("pom cert: %v\n", cert.Subject)
	}
}

func SaveClientUpdate(update *monitor.ClientUpdate) {
	// Store client update in a local folder (miniclient/data/update_{period}.json)
	err := os.MkdirAll("miniclient/data/", os.ModePerm)
	if err != nil {
		fmt.Printf("Unable to create data folder to store updates")
	}
	util.WriteData("miniclient/data/update_"+update.Period+".json", update)
}
