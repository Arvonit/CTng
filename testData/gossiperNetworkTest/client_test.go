package testData

/*
Codeowners:
Finn - Wrote and designed all functions
*/

import (
	"CTng/config"
	"CTng/gossip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// Makes a dummy STH that has garbage values insides for gossipers to react to.
func makeFakeSTH(c *config.Gossiper_config) gossip.Gossip_object {
	payload := "{\"tree_size\":46466472,\"timestamp\":1480512258330,\"sha256_root_hash\":\"LcGcZRsm+LGYmrlyC5LXhV1T6OD8iH5dNlb0sEJl9bA=\"}"
	sig, err := c.Crypto.ThresholdSign(payload)
	if err != nil {
		fmt.Println(err)
	}

	return gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.STH,
		Signer:      string(c.Crypto.SelfID),
		Signature:   [2]string{sig.String(), ""},
		Timestamp:   gossip.GetCurrentTimestamp(),
		// Payload:     [2]string{payload, ""},
	}
}

//Makes an accusation that's been signed with the crypto files of gossiper 3.
func makeAccusation(c *config.Gossiper_config) gossip.Gossip_object {
	sig, err := c.Crypto.ThresholdSign("localhost:8083")
	if err != nil {
		fmt.Println(err)
	}
	return gossip.Gossip_object{
		Application: "Ctng",
		// Type:        gossip.ACCUSATION_FRAG,
		Signer:      string(c.Crypto.SelfID),
		Signature:   [2]string{sig.String(), ""},
		Timestamp:   gossip.GetCurrentTimestamp(),
		// Payload:     [2]string{"localhost:8083", ""},
	}
}

// For sending
func sendObj(c *config.Gossiper_config, obj gossip.Gossip_object) {
	jsonmsg, err := json.Marshal(obj)
	if err != nil {
		fmt.Println(err)
	}
	resp, err := http.Post("http://localhost:8082/gossip/gossip-data", "application/json", bytes.NewBuffer(jsonmsg))
	if err != nil {
		fmt.Println(err)
	} else {
		defer resp.Body.Close()
		fmt.Println("Got Status " + resp.Status)
	}
}

//This is structured as a test so we can run it without using the main entrypoint of the application.
func TestMain(m *testing.M) {
	pub := "gossiper_pub_config.json"
	priv := "2/gossiper_priv_config.json"
	crypto := "2/gossiperCrypto.json"
	c, err := config.LoadGossiperConfig(pub, priv, crypto)
	if err != nil {
		fmt.Println(err)
	}

	sth := makeFakeSTH(&c)
	sendObj(&c, sth)
	// Test sending an accusation
	// obj := makeAccusation(&c)
	// sendObj(&c, obj)
}
