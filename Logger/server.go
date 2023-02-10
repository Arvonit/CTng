package Logger



import (
	"CTng/gossip"
	//"CTng/crypto"
	//"CTng/util"
	//"CTng/config"
	"CTng/CA"
	"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	"crypto/x509"
	"log"
	"net/http"
	"time"
	//"strings"
	"strconv"
	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"



//bind Logger context to the function
func bindLoggerContext(context *LoggerContext, fn func(context *LoggerContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleLoggerRequests(ctx *LoggerContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions
	
	// receive precerts from CA
	gorillaRouter.HandleFunc("/Logger/receive-precerts", bindLoggerContext(ctx, receive_pre_cert)).Methods("POST")
	// get sth request from Monitor
	gorillaRouter.HandleFunc("/ctng/v2/get-sth", bindLoggerContext(ctx, requestSTH)).Methods("GET")
	//start the HTTP server
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+ctx.Logger_private_config.Port, nil))
}

func requestSTH(c *LoggerContext, w http.ResponseWriter, r *http.Request){
	// get current period
	Period := gossip.GetCurrentPeriod()
	c.Request_Count++
	switch c.Logger_Type {
	case 0:
		// normal logger
		json.NewEncoder(w).Encode(c.STH_storage[Period])
	case 1:
		// split-world logger
		if c.Request_Count % c.MisbehaviorInterval == 0 {
			// misbehave
			json.NewEncoder(w).Encode(c.STH_storage_fake[Period])
		}
	case 2:
		// ALways unresponsive logger
		// do nothing
		return
	case 3:
		// sometimes unresponsive logger
		if c.Request_Count % c.MisbehaviorInterval == 0 {
			// misbehave
			return
		}
	}
}




// receive precert from CA
func receive_pre_cert(c *LoggerContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into a precert
	var precert x509.Certificate
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&precert)
	if err != nil {
		panic(err)
	}
	// add to precert pool
	c.CurrentPrecertPool.AddCert(&precert)
	fmt.Println("Received precert from CA")
}

// send STH to CA
func Send_STH_to_CA(c *LoggerContext, sth *STH, ca string){
	var sth_json []byte
	sth_json, err := json.Marshal(sth)
	if err != nil {
		log.Fatalf("Failed to marshal STH: %v", err)
	}
	resp, err := c.Client.Post(PROTOCOL+ ca +"/CA/receive-sth", "application/json", bytes.NewBuffer(sth_json))
	if err != nil {
		log.Fatalf("Failed to send STH to CA: %v", err)
	}
	defer resp.Body.Close()
}


// Send one POI to CA
func Send_POI_to_CA(c *LoggerContext, poi *CA.POI, ca string){
	var poi_json []byte
	poi_json, err := json.Marshal(poi)
	if err != nil {
		log.Fatalf("Failed to marshal POI: %v", err)
	}
	resp, err := c.Client.Post(PROTOCOL+ca+"/CA/receive-poi", "application/json", bytes.NewBuffer(poi_json))
	if err != nil {
		log.Fatalf("Failed to send POI to CA: %v", err)
	}
	defer resp.Body.Close()
}

func Send_POIs_to_CAs(c *LoggerContext, MerkleNodes []MerkleNode){
	//iterate over the MerkleNodes
	for i := 0; i < len(MerkleNodes); i++ {
		// create POI, using merkle node.ProofofInclusion and node.SubjectKeyId
		poi := &CA.POI{ProofOfInclusion: MerkleNodes[i].Poi, SubjectKeyId:MerkleNodes[i].SubjectKeyId}
		// Get the Issuer CA 
		ca := MerkleNodes[i].Issuer
		// send POI to CA
		Send_POI_to_CA(c, poi, ca)
	}
}



func GetCurrentPeriod() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Miniutes, err := strconv.Atoi(timerfc[14:16])
	Periodnum := strconv.Itoa(Miniutes)
	if err != nil {
	}
	return Periodnum
}

func GerCurrentSecond() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Second, err := strconv.Atoi(timerfc[17:19])
	Secondnum := strconv.Itoa(Second)
	if err != nil {
	}
	return Secondnum
}

// Periodic task
func PeriodicTask(ctx *LoggerContext) {
	f := func() {
		PeriodicTask(ctx)
	}
	time.AfterFunc(time.Duration(ctx.Logger_public_config.MMD)*time.Second, f)
	f1 := func() {
		fmt.Println(GerCurrentSecond())
		fmt.Println(time.Now().UTC().Format(time.RFC3339))
		fmt.Println("Logger Periodic Task", GetCurrentPeriod(), "has been online for", ctx.OnlinePeriod, "periods")
		ctx.OnlinePeriod = ctx.OnlinePeriod + 1
	}
	time.AfterFunc(time.Duration(ctx.Logger_public_config.MMD-5)*time.Second, f1)
}


// Start the logger
func StartLogger(c *LoggerContext) {
	// set up HTTP client
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// start at second 0
	currentsecond := GerCurrentSecond()
	// if current second is not 0
	if currentsecond != "0" {
		// wait for 60 - current second
		second, err := strconv.Atoi(currentsecond)
		if err != nil {
		}
		second = 60 - second
		//print wait time
		fmt.Println("Logger will start after", second, "seconds")
		//time.Sleep(time.Duration(second) * time.Second)
	}
	// handle request and wait 55 seconds
	go PeriodicTask(c)
	handleLoggerRequests(c)
}