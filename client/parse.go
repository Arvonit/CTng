package client

import (
	"CTng/CA"
	"CTng/gossip"
	"CTng/util"
	"encoding/json"
	"fmt"
	"github.com/bits-and-blooms/bitset"
)

func Get_SRH_and_DCRV(rev gossip.Gossip_object) (string, bitset.BitSet) {
	var revocation CA.Revocation
	err := json.Unmarshal([]byte(rev.Payload[2]), &revocation)
	if err != nil {
		fmt.Println(err)
	}
	newSRH := revocation.SRH
	var newDCRV bitset.BitSet
	err = newDCRV.UnmarshalBinary(revocation.Delta_CRV)
	if err != nil {
		fmt.Println(err)
	}
	return newSRH, newDCRV
}

type SRH struct {
	Signature string `json:"sig"`
	Id        string `json:"id"`
}

func GetPayload(data MonitorData) []CA.Revocation {
	var out []CA.Revocation

	// Iterate over each REV
	for _, sth := range data {
		// Parse payload[2] field in the REV as a map and extract the DeltaCRV value
		// var payloadRaw map[string]string
		// err := json.Unmarshal([]byte(sth.Payload[2]), &payloadRaw)
		// if err != nil {
		// 	fmt.Println(err)
		// 	return out
		// }

		// Parse payload[2] field in the REV as a Revocation
		var payload CA.Revocation
		err := json.Unmarshal([]byte(sth.Payload[2]), &payload)
		if err != nil {
			// fmt.Println(payload)
			fmt.Println(err)
			return out
		}
		// payload.Delta_CRV = []byte(payloadRaw["Delta_CRV"])

		out = append(out, payload)
	}
	return out
}

func GetDeltaCRV(data MonitorData) []bitset.BitSet {
	payload := GetPayload(data)
	return util.Map(payload, func(p CA.Revocation) bitset.BitSet {
		var deltaCRV bitset.BitSet
		// fmt.Println(string(p.Delta_CRV))

		err := deltaCRV.UnmarshalBinary(p.Delta_CRV)
		if err != nil {
			fmt.Println(err)
		}
		return deltaCRV
	})
}

func GetSRH(data MonitorData) []SRH {
	payload := GetPayload(data)
	return util.Map(payload, func(p CA.Revocation) SRH {
		var srh SRH
		err := json.Unmarshal([]byte(p.SRH), &srh)
		if err != nil {
			fmt.Println(err)
		}
		return srh
	})
}

func GetRootHash(data MonitorData) []string {
	var out []string

	// Iterate over each REV
	for _, sth := range data {
		// Parse the payload field in the REV as a map
		var payload map[string]any
		err := json.Unmarshal([]byte(sth.Payload[1]), &payload)
		if err != nil {
			// fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		// Parse Root Hash value as a string and append it to the array
		out = append(out, payload["RootHash"].(string))
	}

	return out
}
