package monitor

import (
	"CTng/gossip"
	//"CTng/crypto"
	"CTng/util"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	//"strings"
	"strconv"
	//"github.com/gorilla/mux"
)

func receiveGossip(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Post request, parse sent object.
	body, err := ioutil.ReadAll(r.Body)
	// If there is an error, post the error and terminate.
	if err != nil {
		panic(err)
	}
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj gossip.Gossip_object
	err = json.NewDecoder(r.Body).Decode(&gossip_obj)
	// Prints the body of the post request to the server console
	log.Println(string(body))
	// Use a mapped empty interface to store the JSON object.
	var postData map[string]interface{}
	// Decode the JSON object stored in the body
	err = json.Unmarshal(body, &postData)
	// If there is an error, post the error and terminate.
	if err != nil {
		panic(err)
	}
}

func handle_gossip_from_gossiper(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	var gossip_obj gossip.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if c.IsDuplicate(gossip_obj) {
		// If the object is already stored, still return OK.{
		//fmt.Println("Duplicate:", gossip.TypeString(gossip_obj.Type), util.GetSenderURL(r)+".")
		http.Error(w, "Gossip object already stored.", http.StatusOK)
		// processDuplicateObject(c, gossip_obj, stored_obj)
		return
	} else {
		fmt.Println("Recieved new, valid", gossip.TypeString(gossip_obj.Type), "from gossiper.")
		Process_valid_object(c, gossip_obj)
	}
}
func handle_gossip(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Parse sent object.
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj gossip.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	// Verify the object is valid.
	err = gossip_obj.Verify(c.Config.Crypto)
	if err != nil {
		fmt.Println("Recieved invalid object from " + util.GetSenderURL(r) + ".")
		AccuseEntity(c, gossip_obj.Signer)
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	// Check for duplicate object.
	if c.IsDuplicate(gossip_obj) {
		// If the object is already stored, still return OK.{
		//fmt.Println("Duplicate:", gossip.TypeString(gossip_obj.Type), util.GetSenderURL(r)+".")
		http.Error(w, "Gossip object already stored.", http.StatusOK)
		// processDuplicateObject(c, gossip_obj, stored_obj)
		return
	} else {
		fmt.Println("Recieved new, valid", gossip_obj.Type, ".")
		Process_valid_object(c, gossip_obj)
	}
	http.Error(w, "Gossip object Processed.", http.StatusOK)
}

func handle_num_full(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Get the number of full objects stored.
	var num_full gossip.NUM_FULL
	err := json.NewDecoder(r.Body).Decode(&num_full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	// Verify the object is valid.
	/*
		err = num_full.Verify(c.Config.Crypto)
		if err != nil {
			fmt.Println("Recieved invalid NUM_FULL from " + util.GetSenderURL(r) + ".")
			http.Error(w, err.Error(), http.StatusOK)
			return
		}
	*/
	// Check for duplicate object.
	c.Storage_NUM_FULL = &num_full
	http.Error(w, "NUM_FULL Processed.", http.StatusOK)
}

func QueryLoggers(c *MonitorContext) {
	for _, logger := range c.Config.Logger_URLs {
		// var today = time.Now().UTC().Format(time.RFC3339)[0:10]
		if Check_entity_pom(c, logger) {
			fmt.Println(util.RED, "There is a PoM against this Logger. Query will not be initiated", util.RESET)
		} else {
			fmt.Println(util.GREEN + "Querying Logger Initiated" + util.RESET)
			sthResp, err := http.Get(PROTOCOL + logger + "/ctng/v2/get-sth/")
			if err != nil {
				//log.Println(util.RED+"Query Logger Failed: "+err.Error(), util.RESET)
				log.Println(util.RED+"Query Logger Failed, connection refused.", util.RESET)
				AccuseEntity(c, logger)
				continue
			}

			sthBody, err := ioutil.ReadAll(sthResp.Body)
			var STH gossip.Gossip_object
			err = json.Unmarshal(sthBody, &STH)
			if err != nil {
				log.Println(util.RED+err.Error(), util.RESET)
				AccuseEntity(c, logger)
				continue
			}
			err = STH.Verify(c.Config.Crypto)
			if err != nil {
				log.Println(util.RED+"STH signature verification failed", err.Error(), util.RESET)
				AccuseEntity(c, logger)
			} else {

				Process_valid_object(c, STH)
			}
		}
	}

}

// Queries CAs for revocation information
// The revocation datapath hasn't been very fleshed out currently, nor has this function.
func QueryAuthorities(c *MonitorContext) {
	for _, CA := range c.Config.CA_URLs {

		// Get today's revocation information from CA.
		// Get today's date in format YYYY-MM-DD
		// var today = time.Now().UTC().Format(time.RFC3339)[0:10]
		if Check_entity_pom(c, CA) {
			fmt.Println(util.RED, "There is a PoM against this CA. Query will not be initiated", util.RESET)
		} else {
			fmt.Println(util.GREEN + "Querying CA Initiated" + util.RESET)
			revResp, err := http.Get(PROTOCOL + CA + "/ctng/v2/get-revocation/")
			if err != nil {
				//log.Println(util.RED+"Query CA failed: "+err.Error(), util.RESET)
				log.Println(util.RED+"Query CA Failed, connection refused.", util.RESET)
				AccuseEntity(c, CA)
				continue
			}

			revBody, err := ioutil.ReadAll(revResp.Body)
			if err != nil {
				log.Println(util.RED+err.Error(), util.RESET)
				AccuseEntity(c, CA)
			}
			//rev := string(revBody)
			//fmt.Println("Revocation information from CA " + CA + ": " + rev + "\n")
			var REV gossip.Gossip_object
			err = json.Unmarshal(revBody, &REV)
			if err != nil {
				log.Println(util.RED+err.Error(), util.RESET)
				AccuseEntity(c, CA)
				continue
			}
			//fmt.Println(c.Config.Public)
			err = REV.Verify(c.Config.Crypto)
			if err != nil {
				log.Println(util.RED+"Revocation information signature verification failed", err.Error(), util.RESET)
				AccuseEntity(c, CA)
			} else {
				Process_valid_object(c, REV)
			}
		}
	}

}

//This function accuses the entity if the domain name is provided
//It is called when the gossip object received is not valid, or the monitor didn't get response when querying the logger or the CA
//Accused = Domain name of the accused entity (logger etc.)
func AccuseEntity(c *MonitorContext, Accused string) {
	if Check_entity_pom(c, Accused) {
		return
	}
	msg := Accused
	var payloadarray [3]string
	payloadarray[0] = msg
	payloadarray[1] = ""
	payloadarray[2] = ""
	signature, _ := c.Config.Crypto.Sign([]byte(payloadarray[0] + payloadarray[1] + payloadarray[2]))
	var sigarray [2]string
	sigarray[0] = signature.String()
	sigarray[1] = ""
	accusation := gossip.Gossip_object{
		Application:   "CTng",
		Type:          gossip.ACC,
		Period:        gossip.GetCurrentPeriod(),
		Signer:        c.Config.Crypto.SelfID.String(),
		Timestamp:     gossip.GetCurrentTimestamp(),
		Signature:     sigarray,
		Crypto_Scheme: "RSA",
		Payload:       payloadarray,
	}
	//fmt.Println(util.BLUE+"New accusation from ",accusation.Signer, c.Config.Crypto.SignaturePublicMap[signature.ID], "generated, Sending to gossiper"+util.RESET)
	Send_to_gossiper(c, accusation)
}

//Send the input gossip object to its gossiper
func Send_to_gossiper(c *MonitorContext, g gossip.Gossip_object) {
	// Convert gossip object to JSON
	msg, err := json.Marshal(g)
	if err != nil {
		fmt.Println(err)
	}
	// Send the gossip object to the gossiper.
	resp, postErr := c.Client.Post(PROTOCOL+c.Config.Gossiper_URL+"/gossip/gossip-data", "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println(util.RED+"Error sending object to Gossiper: ", postErr.Error(), util.RESET)
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		fmt.Println(util.BLUE+"Sent", gossip.TypeString(g.Type), "to Gossiper, Recieved "+resp.Status, util.RESET)
	}

}

func Send_POM_NUM_to_gossiper(c *MonitorContext, num gossip.NUM) {
	// Convert gossip object to JSON
	msg, err := json.Marshal(num)
	if err != nil {
		fmt.Println(err)
	}
	// Send the gossip object to the gossiper.
	resp, postErr := c.Client.Post(PROTOCOL+c.Config.Gossiper_URL+"/gossip/num", "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println(util.RED+"Error sending object to Gossiper: ", postErr.Error(), util.RESET)
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		fmt.Println(util.BLUE+"Sent PoM_NUM to Gossiper, Recieved "+resp.Status, util.RESET)
	}

}

//this function takes the name of the entity as input and check if there is a POM against it
//this should be invoked after the monitor receives the information from its loggers and CAs prior to threshold signning it
func Check_entity_pom(c *MonitorContext, Accused string) bool {
	GID := gossip.Gossip_ID{
		Period:     gossip.GetCurrentPeriod(),
		Type:       gossip.ACC_FULL,
		Entity_URL: Accused,
	}
	if _, ok := (*c.Storage_ACCUSATION_POM)[GID]; ok {
		fmt.Println(util.BLUE + "Entity has Accusation_PoM on file, no need for more accusations." + util.RESET)
		return true
	}
	GID2 := gossip.Gossip_ID{
		Period:     "0",
		Type:       gossip.CON_FULL,
		Entity_URL: Accused,
	}
	if _, ok := (*c.Storage_CONFLICT_POM)[GID2]; ok {
		fmt.Println(util.BLUE + "Entity has Conflict_PoM on file, no need for more accusations." + util.RESET)
		return true
	}
	return false
}

func IsLogger(c *MonitorContext, loggerURL string) bool {
	for _, url := range c.Config.Public.All_Logger_URLs {
		if url == loggerURL {
			return true
		}
	}
	return false
}

func IsAuthority(c *MonitorContext, authURL string) bool {
	for _, url := range c.Config.Public.All_CA_URLs {
		if url == authURL {
			return true
		}
	}
	return false
}

func GenerateUpdate(c *MonitorContext) (ClientUpdate, gossip.NUM) {
	storageList_conflict_pom := []gossip.Gossip_object{}
	storageList_accusation_pom := []gossip.Gossip_object{}
	storageList_sth_full := []gossip.Gossip_object{}
	storageList_rev_full := []gossip.Gossip_object{}
	for _, gossipObject := range *c.Storage_CONFLICT_POM_DELTA {
		storageList_conflict_pom = append(storageList_conflict_pom, gossipObject)
	}
	for _, gossipObject := range *c.Storage_ACCUSATION_POM {
		storageList_accusation_pom = append(storageList_accusation_pom, gossipObject)
	}
	for _, gossipObject := range *c.Storage_STH_FULL {
		storageList_sth_full = append(storageList_sth_full, gossipObject)
	}
	for _, gossipObject := range *c.Storage_REV_FULL {
		storageList_rev_full = append(storageList_rev_full, gossipObject)
	}
	num_acc_full := strconv.Itoa(len(storageList_accusation_pom))
	num_com_full := strconv.Itoa(len(storageList_conflict_pom))
	NUM := gossip.NUM{
		NUM_ACC_FULL:   num_acc_full,
		NUM_CON_FULL:   num_com_full,
		Period:         gossip.GetCurrentPeriod(),
		Signer_Monitor: c.Config.Crypto.SelfID.String(),
		Crypto_Scheme:  "rsa",
	}
	signature, _ := c.Config.Crypto.Sign([]byte(NUM.NUM_ACC_FULL + NUM.NUM_CON_FULL + NUM.Period + NUM.Signer_Monitor))
	NUM.Signature = signature.String()
	CTupdate := ClientUpdate{
		STHs:      storageList_sth_full,
		REVs:      storageList_rev_full,
		ACCs:      storageList_accusation_pom,
		CONs:      storageList_conflict_pom,
		MonitorID: c.Config.Signer,
		NUM:       NUM,
		NUM_FULL:  *c.Storage_NUM_FULL,
		Period:    gossip.GetCurrentPeriod(),
	}
	return CTupdate, NUM
}

func PeriodicTasks(c *MonitorContext) {
	// Immediately queue up the next task to run at next MMD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	f := func() {
		PeriodicTasks(c)
	}
	time.AfterFunc(time.Duration(c.Config.Public.MMD)*time.Second, f)
	// Run the periodic tasks.
	QueryLoggers(c)
	QueryAuthorities(c)
	f1 := func() {
		c.Clean_Conflicting_Object()
		c.WipeStorage()
		update, NUM := GenerateUpdate(c)
		c.SaveStorage(gossip.GetCurrentPeriod(), update)
		f2 := func() {
			Send_POM_NUM_to_gossiper(c, NUM)
		}
		time.AfterFunc(time.Duration(20)*time.Second, f2)
	}
	time.AfterFunc(time.Duration(c.Config.Public.MMD-20)*time.Second, f1)
}

//This function is called by handle_gossip in monitor_server.go under the server folder
//It will be called if the gossip object is validated
func Process_valid_object(c *MonitorContext, g gossip.Gossip_object) {
	//This handles the STHS from querying loggers
	if g.Type == gossip.STH && IsLogger(c, g.Signer) {
		// Send an unsigned copy to the gossiper if the STH is from the logger
		//fmt.Println(g.Signature[0])
		Send_to_gossiper(c, g)
	}
	//this handles revocation information from querying CAs
	if g.Type == gossip.REV && IsAuthority(c, g.Signer) {
		// Send an unsigned copy to the gossiper if the REV is received from a CA
		Send_to_gossiper(c, g)
	}
	//this handles processed gossip object from the gossiper, verfications will be added when if needed
	if g.Type == gossip.ACC_FULL || g.Type == gossip.CON_FULL || g.Type == gossip.STH_FULL || g.Type == gossip.REV_FULL {
		c.StoreObject(g)
	}
	return
}
