package monitor

import (
	"CTng/gossip"
	"CTng/crypto"
	"CTng/util"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"strings"
	"strconv"
	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"
func bindMonitorContext(context *MonitorContext, fn func(context *MonitorContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleMonitorRequests(c *MonitorContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions
	gorillaRouter.HandleFunc("/monitor/get-updates/", bindMonitorContext(c, requestupdate)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/recieve-gossip", bindMonitorContext(c, handle_gossip)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/recieve-gossip-from-gossiper", bindMonitorContext(c, handle_gossip_from_gossiper)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Config.Port, nil))
}

type Clientupdate struct{
	STHs *gossip.Gossip_Storage
	REVs *gossip.Gossip_Storage
	PoMs *gossip.Gossip_Storage
	MonitorID string
	//Period here means the update period, the client udpate object can contain more information than just the period 
	Period string
	PoMsig string
}

type Clientquery struct{
	Client_URL string
	LastUpdatePeriod string
}
//This function should be invoked after the monitor-gossiper system converges in this period
func PrepareClientupdate(c *MonitorContext,LastUpdatePeriod string) Clientupdate{
	LastUpdatePeriodint, _ := strconv.Atoi(LastUpdatePeriod)
	CurrentPeriodint, _:= strconv.Atoi(gossip.GetCurrentPeriod())
	//intialize some storages
	storage_conflict_pom := new(gossip.Gossip_Storage)
	*storage_conflict_pom  = make(gossip.Gossip_Storage)
	storage_sth_full := new(gossip.Gossip_Storage)
	*storage_sth_full  = make(gossip.Gossip_Storage)
	storage_rev_full := new(gossip.Gossip_Storage)
	*storage_rev_full  = make(gossip.Gossip_Storage)
	//load all poms and sign on it
	for _, gossipObject := range *storage_conflict_pom{
		(*storage_conflict_pom)[gossipObject.GetID()] = gossipObject
	}
	payload,_ := json.Marshal(*storage_conflict_pom)
	signature, _ := crypto.RSASign([]byte(payload), &c.Config.Crypto.RSAPrivateKey, c.Config.Crypto.SelfID)
	//load all STHs (Fully Threshold signed) from lastUpdatePeriod to the current period
	for _, gossipObject := range *storage_sth_full{
		for i := LastUpdatePeriodint; i < CurrentPeriodint; i++ {
			if gossipObject.Period == strconv.Itoa(i){
				(*storage_sth_full)[gossipObject.GetID()] = gossipObject
			}
		}
	}
	//load all REVs (Fully Threshold signed) from LastUpdatePeriod to the current period
	for _, gossipObject := range *storage_rev_full{
		for i := LastUpdatePeriodint; i < CurrentPeriodint; i++ {
			if gossipObject.Period == strconv.Itoa(i){
				(*storage_rev_full)[gossipObject.GetID()] = gossipObject
			}
		}
	}
	CTupdate := Clientupdate{
		STHs: storage_sth_full,
		REVs: storage_rev_full,
		PoMs: storage_conflict_pom,
		MonitorID: c.Config.Signer,
		Period: gossip.GetCurrentPeriod(),
		PoMsig: signature.String(),
	}
	return CTupdate
}

func requestupdate(c *MonitorContext, w http.ResponseWriter, r *http.Request){
	var ticket Clientquery
	err := json.NewDecoder(r.Body).Decode(&ticket)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	var ctupdate = PrepareClientupdate(c,ticket.LastUpdatePeriod)
	msg, _ := json.Marshal(ctupdate)
	resp, postErr := c.Client.Post("http://"+ticket.Client_URL+"/receive-updates", "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println("Error sending update to client: " + postErr.Error())
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		if c.Verbose {
			fmt.Println("Client responded with " + resp.Status)
		}
	}

}
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

func handle_gossip_from_gossiper(c *MonitorContext, w http.ResponseWriter, r *http.Request){
	var gossip_obj gossip.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if c.IsDuplicate(gossip_obj){
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
	if c.IsDuplicate(gossip_obj){
		// If the object is already stored, still return OK.{
		//fmt.Println("Duplicate:", gossip.TypeString(gossip_obj.Type), util.GetSenderURL(r)+".")
		http.Error(w, "Gossip object already stored.", http.StatusOK)
		// processDuplicateObject(c, gossip_obj, stored_obj)
		return
	} else {
		fmt.Println("Recieved new, valid", gossip_obj.Type,".")
		Process_valid_object(c, gossip_obj)
		c.SaveStorage()
	}
	http.Error(w, "Gossip object Processed.", http.StatusOK)
}


func QueryLoggers(c *MonitorContext) {
	for _, logger := range c.Config.Logger_URLs {
		// var today = time.Now().UTC().Format(time.RFC3339)[0:10]
		if Check_entity_pom(c, logger){
			fmt.Println(util.RED,"There is a PoM against this Logger. Query will not be initiated",util.RESET)
		}else
		{
			fmt.Println(util.GREEN + "Querying Logger Initiated" + util.RESET)
			sthResp, err := http.Get(PROTOCOL + logger + "/ctng/v2/get-sth/")
			if err != nil {
				//log.Println(util.RED+"Query Logger Failed: "+err.Error(), util.RESET)
				log.Println(util.RED+"Query Logger Failed, connection refused.",util.RESET)
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
		if Check_entity_pom(c, CA){
			fmt.Println(util.RED,"There is a PoM against this CA. Query will not be initiated",util.RESET)
		}else
		{
			fmt.Println(util.GREEN + "Querying CA Initiated" + util.RESET)
			revResp, err := http.Get(PROTOCOL + CA + "/ctng/v2/get-revocation/")
			if err != nil {
				//log.Println(util.RED+"Query CA failed: "+err.Error(), util.RESET)
				log.Println(util.RED+"Query CA Failed, connection refused.",util.RESET)
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
	if Check_entity_pom(c,Accused){
		return
	}
	msg := Accused
	var payloadarray [3]string
	payloadarray[0] = msg
	payloadarray[1] = ""
	payloadarray[2] = ""
	signature, _ := c.Config.Crypto.ThresholdSign(payloadarray[0]+payloadarray[1]+payloadarray[2])
	var sigarray [2]string
	sigarray[0] = signature.String()
	sigarray[1] = ""
	accusation := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.ACC_FRAG,
		Period:      gossip.GetCurrentPeriod(),
		Signer:      c.Config.Crypto.SelfID.String(),
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   sigarray,
		Crypto_Scheme: "BLS",
		Payload:     payloadarray,
	}
	fmt.Println(util.BLUE+"New accusation generated, Sending to gossiper"+util.RESET)
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
		fmt.Println(util.RED+"Error sending object to Gossiper: ", postErr.Error(),util.RESET)
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		fmt.Println(util.BLUE+"Sent", gossip.TypeString(g.Type), "to Gossiper, Recieved "+resp.Status, util.RESET)
	}

}

//this function takes the name of the entity as input and check if there is a POM against it
//this should be invoked after the monitor receives the information from its loggers and CAs prior to threshold signning it
func Check_entity_pom(c *MonitorContext, Accused string) bool {
	GID := gossip.Gossip_ID{
		Period: gossip.GetCurrentPeriod(),
		Type: gossip.ACCUSATION_POM,
		Entity_URL: Accused,
	}
	if _,ok := (*c.Storage_ACCUSATION_POM)[GID]; ok{
		fmt.Println(util.BLUE+"Entity has Accusation_PoM on file, no need for more accusations."+util.RESET)
		return true
	}
	GID2 := gossip.Gossip_ID{
		Period: "0",
		Type: gossip.CONFLICT_POM,
		Entity_URL: Accused,
	}
	if _,ok := (*c.Storage_CONFLICT_POM)[GID2]; ok{
		fmt.Println(util.BLUE+"Entity has Conflict_PoM on file, no need for more accusations."+util.RESET)
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
	c.WipeStorage()
	c.Clean_Conflicting_Object()
	c.SaveStorage()
	//wait for some time (after all the monitor-gossip system converges)
	//time.Sleep(10*time.Second);
}

func InitializeMonitorStorage(c *MonitorContext){
	if c.StorageDirectory == "" {
		c.StorageDirectory = "testData/monitordata/"+c.StorageID+"/"
	}
	
	c.StorageFile_CONFLICT_POM  = "CONFLICT_POM.json"
	c.StorageFile_ACCUSATION_POM = "ACCUSATION_POM.json"
	c.StorageFile_STH_FULL = "STH_FULL.json"
	c.StorageFile_REV_FULL = "REV_FULL.json" 
	util.CreateFile(c.StorageDirectory+c.StorageFile_CONFLICT_POM)
	util.CreateFile(c.StorageDirectory+c.StorageFile_ACCUSATION_POM)
	util.CreateFile(c.StorageDirectory+c.StorageFile_STH_FULL)
	util.CreateFile(c.StorageDirectory+c.StorageFile_REV_FULL)

}

//This function is called by handle_gossip in monitor_server.go under the server folder
//It will be called if the gossip object is validated
func Process_valid_object(c *MonitorContext, g gossip.Gossip_object) {
	c.StoreObject(g)
	//This handles the STHS
	if g.Type == gossip.STH {
		// Send an unsigned copy to the gossiper if the STH is from the logger
		if IsLogger(c, g.Signer){
			Send_to_gossiper(c, g)
		}
		// The below function for creates the SIG_FRAG object
		f := func() {
			sig_frag, err := c.Config.Crypto.ThresholdSign(g.Payload[0]+g.Payload[1]+g.Payload[2])
			if err != nil {
				fmt.Println(err.Error())
			}
			pom_err := Check_entity_pom(c, g.Signer)
			//if there is no conflicting information/PoM send the Threshold signed version to the gossiper
			if pom_err == false {
				fmt.Println(util.BLUE, "Signing STH of", g.Signer, util.RESET)
				g.Type = gossip.STH_FRAG
				g.Signature[0] = sig_frag.String()
				g.Signer = c.Config.Crypto.SelfID.String()
				Send_to_gossiper(c, g)
			} else {
				fmt.Println(util.RED, "Conflicting information/PoM found, not sending STH_FRAG", util.RESET)
			}

		}
		// Delay the calling of f until gossip_wait_time has passed.
		time.AfterFunc(time.Duration(c.Config.Public.Gossip_wait_time)*time.Second, f)
		return
	}
	//if the object is from a CA, revocation information
	//this handles revocation information
	if  g.Type == gossip.REV{
		// Send an unsigned copy to the gossiper if the REV is received from a CA
		if IsAuthority(c, g.Signer){
			Send_to_gossiper(c, g)
		}
		f := func() {
			sig_frag, err := c.Config.Crypto.ThresholdSign(g.Payload[0]+g.Payload[1]+g.Payload[2])
			if err != nil {
				fmt.Println(err.Error())
			}
			fmt.Println(util.BLUE, "Signing Revocation of", g.Signer, util.RESET)
			pom_err := Check_entity_pom(c, g.Signer)
			if pom_err == false {
				g.Type = gossip.REV_FRAG
				g.Signature[0] = sig_frag.String()
				g.Signer = c.Config.Crypto.SelfID.String()
				Send_to_gossiper(c, g)
			}

		}
		time.AfterFunc(time.Duration(c.Config.Public.Gossip_wait_time)*time.Second, f)
		return
	}
	// ACCUSATION_POM, CONFLICT_POM, STH_FULL, REV_FULL should be stored
	//if g.Type == gossip.ACCUSATION_POM || g.Type == gossip.CONFLICT_POM || g.Type == gossip.STH_FULL || g.Type == gossip.REV_FULL{
		//c.StoreObject(g)
		//return
	//}
	return
}

func StartMonitorServer(c *MonitorContext) {
	// Check if the storage file exists in this directory
	// time_wait := gossip.Getwaitingtime();
	// time.Sleep(time.Duration(time_wait)*time.Second);
	
	InitializeMonitorStorage(c)
	err := c.LoadStorage()
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			// Storage File doesn't exit. Create new, empty json file.
			err = c.SaveStorage()
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// Run a go routine to handle tasks that must occur every MMD
	go PeriodicTasks(c)
	// Start HTTP server loop on the main thread
	handleMonitorRequests(c)
}
