package gossip


import (
	"CTng/util"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"CTng/crypto"
	"log"
	"net/http"
	"os"
	"github.com/gorilla/mux"
	"time"
)

type Gossiper interface {

	// Response to entering the 'base page' of a gossiper.
	// TODO: Create informational landing page
	homePage()

	// HTTP POST request, receive a JSON object from another gossiper or connected monitor.
	// /gossip/push-data
	handleGossip(w http.ResponseWriter, r *http.Request)

	// Respond to HTTP GET request.
	// /gossip/get-data
	handleGossipObjectRequest(w http.ResponseWriter, r *http.Request)

	// Push JSON object to connected network from this gossiper via HTTP POST.
	// /gossip/gossip-data
	gossipData()

	// TODO: Push JSON object to connected 'owner' (monitor) from this gossiper via HTTP POST.
	// Sends to an owner's /monitor/recieve-gossip endpoint.
	sendToOwner()

	// Process JSON object received from HTTP POST requests.
	processData()

	// TODO: Erase stored data after one MMD.
	eraseData()

	// HTTP server function which handles GET and POST requests.
	handleRequests()
}

// Binds the context to the functions we pass to the router.
func bindContext(context *GossiperContext, fn func(context *GossiperContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleRequests(c *GossiperContext) {

	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)

	// homePage() is ran when base directory is accessed.
	gorillaRouter.HandleFunc("/gossip/", homePage)

	// Inter-gossiper endpoints
	gorillaRouter.HandleFunc("/gossip/push-data", bindContext(c, handleGossip)).Methods("POST")

	//gorillaRouter.HandleFunc("/gossip/get-data", bindContext(c, handleGossipObjectRequest)).Methods("GET")

	// Monitor interaction endpoint
	gorillaRouter.HandleFunc("/gossip/gossip-data", bindContext(c, handleGossip)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	fmt.Println(util.BLUE+"Listening on port:", c.Config.Port, util.RESET)
	err := http.ListenAndServe("localhost:"+c.Config.Port, nil)
	// We wont get here unless there's an error.
	log.Fatal("ListenAndServe: ", err)
	os.Exit(1)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the base page for the CTng gossiper.")
}
// handleGossip() is ran when POST is recieved at /gossip/push-data.
// It should verify the Gossip object and then send it to the network.
func handleGossip(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	// Parse sent object.
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Verify the object is valid, if invalid we just ignore it
	err = gossip_obj.Verify(c.Config.Crypto)
	if err != nil {
		//fmt.Println("Received invalid object "+TypeString(gossip_obj.Type)+" from " + util.GetSenderURL(r) + ".")
		fmt.Println(util.RED,"Received invalid object "+TypeString(gossip_obj.Type)+ " signed by " + EntityString(gossip_obj.Signer) + ".",util.RESET)
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	// Check for duplicate object.
	stored_obj, found := c.GetObject(gossip_obj.GetID())
	if found && gossip_obj.Signer == stored_obj.Signer{
		// If the object is already stored, still return OK.
		//fmt.Println("Duplicate:", gossip_obj.Type, util.GetSenderURL(r)+".")
		//fmt.Println("Duplicate: ", TypeString(gossip_obj.Type), " signed by ",gossip_obj.Signer+".")
		err := ProcessDuplicateObject(c, gossip_obj, stored_obj)
		if err != nil {
			http.Error(w, err.Error(), http.StatusOK)
			return
		}
		http.Error(w, "Received Duplicate Object."+ TypeString(gossip_obj.Type)+ " signed by " + gossip_obj.Signer+".", http.StatusOK)
		return
	} else {
		//fmt.Println(util.GREEN+"Received new, valid", TypeString(gossip_obj.Type), "from "+util.GetSenderURL(r)+".", util.RESET)
		fmt.Println(util.GREEN,"Received new, valid ",TypeString(gossip_obj.Type), "signed by ",EntityString(gossip_obj.Signer), " at Period ",gossip_obj.Period," regarding ", EntityString(gossip_obj.Payload[0])," .", util.RESET)
		//fmt.Println(gossip_obj.Signature)
		ProcessValidObject(c, gossip_obj)
		c.SaveStorage()
	}
	http.Error(w, "Gossip object Processed.", http.StatusOK)
}


// Sends a gossip object to all connected gossipers.
// This function assumes you are passing valid data. ALWAYS CHECK BEFORE CALLING THIS FUNCTION.
func GossipData(c *GossiperContext, gossip_obj Gossip_object) error {
	// Convert gossip object to JSON
	msg, err := json.Marshal(gossip_obj)
	if err != nil {
		fmt.Println(err)
	}

	// Send the gossip object to all connected gossipers.
	for _, url := range c.Config.Connected_Gossipers {
		//fmt.Println("Attempting to sending data to", url)
		// HTTP POST the data to the url or IP address.
		resp, err := c.Client.Post("http://"+url+"/gossip/push-data", "application/json", bytes.NewBuffer(msg))
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+".", util.RESET)
				// Don't accuse gossipers for inactivity.
				// defer Accuse(c, url)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			continue
		}
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		//fmt.Println("Gossiped to " + url + " and recieved " + resp.Status)
	}
	return nil
}

// Sends a gossip object to the owner of the gossiper.
func SendToOwner(c *GossiperContext, obj Gossip_object) {
	// Convert gossip object to JSON
	msg, err := json.Marshal(obj)
	if err != nil {
		fmt.Println(err)
	}
	// Send the gossip object to the owner.
	resp, postErr := c.Client.Post("http://"+c.Config.Owner_URL+"/monitor/recieve-gossip-from-gossiper", "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println("Error sending object to owner: " + postErr.Error())
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		if c.Verbose {
			fmt.Println("Owner responded with " + resp.Status)
		}
	}
}

// Once an object is verified, it is stored and given its neccessary data path.
// At this point, the object has not yet been stored in the database.
// What we know is that the signature is valid for the provided data.
func ProcessValidObject(c *GossiperContext, obj Gossip_object) {
	// This function is incomplete -- requires more individual object direction
	// Note: Object needs to be stored before Gossiping so it is recognized as a duplicate.
	c.StoreObject(obj)
	var err error = nil
	switch obj.Type {
	case STH:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case REV:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case STH_FRAG:
		err = GossipData(c, obj)
		//fmt.Println("Finshed Gossiping ",obj.Type, ". Starting to process it.")
		Process_TSS_Object(c,obj,STH_FULL)
	case REV_FRAG:
		err = GossipData(c, obj)
		//fmt.Println("Finshed Gossiping ",obj.Type, ". Starting to process it.")
		Process_TSS_Object(c,obj,REV_FULL)
	case ACC_FRAG:
		err = GossipData(c, obj)
		//fmt.Println("Finshed Gossiping ",obj.Type, ". Starting to process it.")
		Process_TSS_Object(c,obj,ACCUSATION_POM)
	case STH_FULL:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case REV_FULL:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case ACCUSATION_POM:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case CONFLICT_POM:
		SendToOwner(c, obj)
		err = GossipData(c, obj)

	default:
		fmt.Println("Recieved unsupported object type.")
	}
	if err != nil {
		// ...
	}
}

// Process a valid gossip object which is a duplicate to another one.
// If the signature/payload is identical, then we can safely ignore the duplicate.
// Otherwise, we generate a PoM for two objects sent in the same period.
func ProcessDuplicateObject(c *GossiperContext, obj Gossip_object, dup Gossip_object) error{
	//If the object has PoM already, it is dead already
	//if c.HasPoM(obj.Payload[0],obj.Period){
		//return nil
	//}
	//If the object type is the same
	//In the same Periord
	//Signed by the same Entity
	//But the signature is different
	//MALICIOUS, you are exposed
	//note PoMs can have different signatures
	if obj.Type == dup.Type && obj.Period == dup.Period && obj.Signer == dup.Signer && obj.Signature[0] != dup.Signature[0] && obj.Type!= CONFLICT_POM && obj.Type != ACCUSATION_POM{
		D2_POM:= Gossip_object{
			Application: obj.Application,
			Type:        CONFLICT_POM,
			Period:      "0",
			Signer:      "",
			Timestamp:   GetCurrentTimestamp(),
			Signature:   [2]string{obj.Signature[0], dup.Signature[0]},
			Payload:     [3]string{obj.Signer, obj.Payload[0]+obj.Payload[1]+obj.Payload[2],dup.Payload[0]+dup.Payload[1]+dup.Payload[2]},
		}
		//store the object and send to monitor
		fmt.Println(util.YELLOW, "Entity: ", D2_POM.Payload[0], " is Malicious!", util.RESET)
		SendToOwner(c,D2_POM)
		c.StoreObject(D2_POM)
		GossipData(c,D2_POM)
	}
	return nil
}

func Process_TSS_Object(gc *GossiperContext, new_obj Gossip_object, target_type string) error{
	c := gc.Config.Crypto
	key := new_obj.GetID()
	//fmt.Println(key)
	newkey:=Gossip_ID{
		Period: key.Period,
		Type: target_type,
		Entity_URL: key.Entity_URL,
	}
	p_sig, err := crypto.SigFragmentFromString(new_obj.Signature[0])
	if err != nil {
		fmt.Println("partial sig conversion error (from string)")
		return err
	}
	//If there is already an STH_FULL Object
	if _, ok:= (*gc.Storage)[newkey]; ok{
		fmt.Println(util.BLUE + "There already exists a "+ TypeString(target_type)+ " Object" + util.RESET)
		return nil
	} 
	//If there isn't a STH_FULL Object yet, but there exists some other sth_frag
	if val, ok := (*gc.Obj_TSS_DB)[key]; ok {
		val.Signers[val.Num] = new_obj.Signer
		if err != nil {
			fmt.Println("partial sig conversion error (from string)")
			return err
		}
		val.Partial_sigs[val.Num] = p_sig
		val.Num = val.Num + 1
		//fmt.Println("Finished updating Counters, the new number is", val.Num)
		//now we check if the number of sigs have reached the threshold
		if val.Num>=c.Threshold{
			TSS_sig, _ := c.ThresholdAggregate(val.Partial_sigs)
			TSS_sig_string,_ := TSS_sig.String()
			sigfield := new([2]string)
			(*sigfield)[0] = TSS_sig_string
			signermap := make(map[int]string)
			for i := 0; i<c.Threshold; i++{
				signermap[i] = val.Signers[i]
			}
			TSS_FULL_obj := Gossip_object{
				Application: new_obj.Application,
				Type:        target_type,
				Period:      new_obj.Period,
				Signer:      "",
				Signers:     signermap,
				Timestamp:   GetCurrentTimestamp(),
				Signature:   *sigfield,
				Crypto_Scheme: "BLS",
				Payload:     new_obj.Payload,
			}
			//Store the POM
			fmt.Println(util.BLUE+TypeString(target_type)+" generated and Stored"+util.RESET)
			gc.StoreObject(TSS_FULL_obj)
			//send to the monitor
			SendToOwner(gc,TSS_FULL_obj)
			return nil
		}
	}
	//if the this is the first STH_FRAG received
	//fmt.Println("This is the first partial sig registered")
	new_counter := new(Entity_Gossip_Object_TSS_Counter)
	*new_counter = Entity_Gossip_Object_TSS_Counter{
		Signers:     []string{new_obj.Signer,""},
		Num:      1,
		Partial_sigs: []crypto.SigFragment{p_sig,p_sig},
	}
	(*gc.Obj_TSS_DB)[key] = new_counter
	//fmt.Println("Number of counters in TSS DB is: ", len(*gc.Obj_TSS_DB))
	return nil

}

func PeriodicTasks(c *GossiperContext) {
	// Immediately queue up the next task to run at next MMD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	f := func() {
		PeriodicTasks(c)
	}
	time.AfterFunc(time.Duration(c.Config.Public.MMD*3)*time.Second, f)
	c.WipeStorage()
}

func InitializeGossiperStorage (c* GossiperContext){
	c.StorageDirectory = "testData/gossiperdata/"+c.StorageID+"/"
	c.StorageFile = "GossipStorage.Json"
	util.CreateFile(c.StorageDirectory+c.StorageFile)

}

func StartGossiperServer(c *GossiperContext) {
	// Check if the storage file exists in this directory
	// Only need to store Degree2_PoM
	InitializeGossiperStorage(c)
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
	// Create the http client to be used.
	// This is thorough and allows for HTTP client configuration,
	// although we don't need it yet.
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// HTTP Server Loop
	go PeriodicTasks(c)
	handleRequests(c)
}
