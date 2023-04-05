package client

import (
	"CTng/CA"
	"CTng/Logger"
	"CTng/util"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	//"io/ioutil"
	"CTng/crypto"
	"CTng/gossip"
	"CTng/monitor"
	"encoding/json"
	"errors"
)

type ProofOfInclusion struct {
	SiblingHashes [][]byte
	NeighborHash  []byte
}

type CTngExtension struct {
	STH gossip.Gossip_object `json:"STH"`
	POI ProofOfInclusion     `json:"POI"`
	RID int                  `json:"RID"`
}

const PROTOCOL = "http://"

func bindClientContext(context *ClientContext, fn func(context *ClientContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func HandleUpdate(c *ClientContext, update monitor.ClientUpdate) {

	fmt.Println(util.GREEN + update.Period + util.RESET)
	fmt.Println(util.GREEN+"update received at ", update.Period, util.RESET)
	HandleSTHs(c, &update.STHs)
	HandleREVs(c, &update.REVs)
	HandleACCs(c, &update.ACCs)
	HandleCONs(c, &update.CONs)
	err := update.NUM.Verify(c.Config.Crypto)
	if err != nil {
		//handle this
	}
	err = update.NUM_FULL.Verify(c.Config.Crypto)
	if err != nil {
		//
	}
	// check NUM_FULL against prev num
	if update.NUM_FULL.NUM_ACC_FULL != c.Storage_NUM.NUM_ACC_FULL ||
		update.NUM.NUM_CON_FULL != c.Storage_NUM.NUM_CON_FULL {
		fmt.Println("Got NUM_FULL != prev NUM")
		return
	}
	c.Storage_NUM = &update.NUM
	c.Storage_NUM_FULL = &update.NUM_FULL
	//update the last update Period
	c.LastUpdatePeriod = update.Period
	//Push the received Signed PoMs to the checking monitor for integrity check
	//var pom_signed SignedPoMs = GetSignedPoMs(c, update)
	//PushtoMonitor(c, pom_signed)
}

func HandleSTHs(c *ClientContext, STHs *[]gossip.Gossip_object) {
	for _, gossipObject := range *STHs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_STH_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleREVs(c *ClientContext, REVs *[]gossip.Gossip_object) {
	for _, gossipObject := range *REVs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_REV_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleACCs(c *ClientContext, ACCs *[]gossip.Gossip_object) {
	for _, gossipObject := range *ACCs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_ACCUSATION_POM)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleCONs(c *ClientContext, CONs *[]gossip.Gossip_object) {
	for _, gossipObject := range *CONs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_CONFLICT_POM)[gossipObject.GetID()] = gossipObject
		}
	}
}

func Parse_CTng_extension(cert *x509.Certificate) *CTngExtension {
	ctng_ext_M := []byte(cert.CRLDistributionPoints[0])
	ctng_UM := new(CTngExtension)
	json.Unmarshal(ctng_ext_M, &ctng_UM)
	return ctng_UM
}

func verifySignatures(
	c *ClientContext,
	cert x509.Certificate,
	conflictPoms *gossip.Gossip_Storage,
	accusationPoms *gossip.Gossip_Storage,
	sths *gossip.Gossip_Storage,
	revs *gossip.Gossip_Storage,
) error {
	rsasig, err := crypto.RSASigFromString(string(cert.Signature))
	if err != nil {
		return errors.New("No_Sig_Match")
	}
	payload, _ := json.Marshal(cert)
	var cryptoconf = *c.Config.Crypto
	result := cryptoconf.Verify([]byte(payload), rsasig)
	if result != nil {
		return result
	}
	for _, pom := range *conflictPoms {
		err := pom.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	for _, pom := range *accusationPoms {
		err := pom.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	for _, sth := range *sths {
		err := sth.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	for _, rev := range *revs {
		err := rev.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkCertAgainstPOMList(cert x509.Certificate, poms *gossip.Gossip_Storage) error {
	if len(*poms) == 0 {
		return nil
	}
	for _, pom := range *poms {
		if cert.Issuer.String() == pom.Payload[0] {
			return errors.New("CA in POM list")
		}
		goodLogger := false
		certLoggers := Parse_CTng_extension(&cert).STH.Signers
		for _, logger := range certLoggers {
			if logger != pom.Payload[0] {
				goodLogger = true
				break
			}
		}
		if !goodLogger {
			return errors.New("No good logger for cert")
		}
	}
	return nil
}

func verifyPOI(sth Logger.STH, poi ProofOfInclusion, cert x509.Certificate) bool {
	return Logger.VerifyPOI(sth, CA.ProofOfInclusion(poi), cert)
}

func VerifyPoMs(c *ClientContext, poms *gossip.Gossip_Storage, sig string) error {
	rsasig, err := crypto.RSASigFromString(sig)
	if err != nil {
		return errors.New("No_Sig_Match")
	}
	payload, _ := json.Marshal(*poms)
	var cryptoconf = *c.Config.Crypto
	result := cryptoconf.Verify([]byte(payload), rsasig)
	fmt.Println(result)
	return result
}

func Start(c *ClientContext) {
	QueryMonitor(c)
	fmt.Println()
	QueryServer(c)
}

func QueryMonitor(c *ClientContext) {
	res, err := FetchClientUpdate("http://localhost:3000/?period=3")
	if err != nil {
		fmt.Printf("client update err: %v\n", err)
		return
	}

	fmt.Printf("monitor id: %v\n", res.MonitorID)
	fmt.Printf("period: %v\n", res.Period)
	fmt.Printf("\nsth: %v\n", res.STHs)
	fmt.Printf("\nrev: %v\n", res.REVs)
	fmt.Printf("\nacc: %v\n", res.CONs)
	fmt.Printf("\ncon: %v\n", res.CONs)

	fmt.Printf("\nnum: %v\n", res.NUM)
	fmt.Printf("\nnum full: %v\n", res.NUM_FULL)

	fmt.Printf("\nsth root hash:\n%v\n", GetRootHash(res.STHs))
	fmt.Printf("\nrev delta crv: %v\n", GetDeltaCRV(res.REVs))
	fmt.Printf("\nrev srh value: %v\n", GetSRH(res.REVs))
	HandleUpdate(c, res)
	SaveClientUpdate(&res)
}

func SaveClientUpdate(update *monitor.ClientUpdate) {
	// Store client update in a local folder (miniclient/data/update_{period}.json)
	err := os.MkdirAll("miniclient/data/", os.ModePerm)
	if err != nil {
		fmt.Printf("Unable to create data folder to store updates")
	}
	util.WriteData("miniclient/data/update_"+update.Period+".json", update)
}

// Deprecated: These endpoints have been removed from the monitor
func QueryMonitorOldEndpoints() {
	// monitorURL := "http://localhost:3000"
	// backupMonitorURL := "http://localhost:3001"

	res, err := FetchGossip("http://localhost:3000/sth")
	sthNumPeriods := len(res)
	if err != nil {
		fmt.Printf("sth err: %v\n", err)
	} else {
		fmt.Printf("sth: %v\n", res)
	}

	res, err = FetchGossip("http://localhost:3000/rev")
	revNumPeriods := len(res)
	if err != nil {
		fmt.Printf("rev err: %v\n", err)
	} else {
		fmt.Printf("rev: %v\n", res)
		fmt.Printf("rev delta crv: %s\n", GetDeltaCRV(res))
		fmt.Printf("rev num periods: %d\n", revNumPeriods)
	}

	res, err = FetchGossip("http://localhost:3000/pom")
	pomNumPeriods := len(res)
	if err != nil {
		fmt.Printf("pom err: %v\n", err)
	} else {
		fmt.Printf("pom: %v\n", res)
		fmt.Printf("pom num periods: %v\n", pomNumPeriods)
	}

	// TODO: Query another monitor?
	if (sthNumPeriods == revNumPeriods) && (sthNumPeriods == pomNumPeriods) {
	}
}

func QueryServer(c *ClientContext) {
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
