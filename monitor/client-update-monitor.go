package monitor

import (
	"CTng/gossip"
	"CTng/util"
	"encoding/json"
	"fmt"
	"net/http"
	//"CTng/crypto"
	//"bytes"
	//"time"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)

type ClientUpdate struct {
	STHs      []gossip.Gossip_object
	REVs      []gossip.Gossip_object
	ACCs      []gossip.Gossip_object
	CONs      []gossip.Gossip_object
	NUM       gossip.NUM
	NUM_FULL  gossip.NUM_FULL
	MonitorID string
	//Period here means the update period, the client udpate object can contain more information than just the period
	Period string
	// PoMsig string
}

func PrepareClientUpdate(context *MonitorContext, filepath string) (*ClientUpdate, error) {
	var clientupdate ClientUpdate
	// read from filepath
	bytes, err := util.ReadByte(filepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &clientupdate)
	if err != nil {
		return nil, err
	}
	return &clientupdate, nil
}

func requestupdate(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	var periodnum string
	err := json.NewDecoder(r.Body).Decode(&periodnum)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	//get the file path
	filepath := c.StorageDirectory + "/Period_" + periodnum + "/ClientUpdate.json"
	ctupdate, _ := PrepareClientUpdate(c, filepath)
	fmt.Println(ctupdate.Period)
	msg, _ := json.Marshal(ctupdate)
	json.NewEncoder(w).Encode(msg)
	fmt.Println("Update request Processed")
}
