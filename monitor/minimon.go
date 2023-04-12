package monitor

import (
	"CTng/gossip"
	// "CTng/monitor"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

// Implements a minimal monitor server. Includes endpoints to retrieve STHs, REVs, and POMs.
func StartMinimon() {
	http.HandleFunc("/", handleClientUpdate)

	// http.HandleFunc("/sth", createRequestHandler("testData/monitordata/1/STH_FULL.json"))
	// http.HandleFunc("/rev", createRequestHandler("testData/monitordata/1/REV_FULL.json"))
	// http.HandleFunc("/pom", createRequestHandler("testData/monitordata/1/CONFLICT_POM.json"))

	fmt.Println("Monitor listening on port 3000...")
	if err := http.ListenAndServe("localhost:3000", nil); err != nil {
		log.Fatal(err)
	}
}

func handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	// Create monitor context from sample monitor configuration
	context := InitializeMonitorContext(
		"Gen/monitor_testconfig/1/Monitor_public_config.json",
		"Gen/monitor_testconfig/1/Monitor_private_config.json",
		"Gen/monitor_testconfig/1/Monitor_crypto_config.json",
		"1",
	)

	// Get the specified period from the query parameter. If in an invalid period is entered
	// or not given, return an error
	periodStr := r.URL.Query().Get("period")
	_, err := strconv.Atoi(periodStr)
	if err != nil {
		http.Error(w, "Period paramater must be an integer", http.StatusBadRequest)
		return
	}

	// Fetch the STH, POM, and REV data corresponding with the specificed period from disk
	update, err := PrepareClientUpdate(
		context,
		"client_test/ClientData/Period "+periodStr+"/FromMonitor/ClientUpdate_at_Period "+periodStr+".json",
	)
	if err != nil {
		http.Error(w, "Period not available", http.StatusBadRequest)
		log.Println(err)
		return
	}

	// Marshal client update and send it if successful
	updateJson, err := json.Marshal(update)
	if err != nil {
		http.Error(w, "Could not marshal client update", http.StatusInternalServerError)
	} else {
		fmt.Fprint(w, string(updateJson))
	}
}

// Create a HTTP request handler to return an array of gossip objects, stored in the given directory
func createRequestHandler(fileName string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// TODO: Replace file location with config object
		content, err := os.ReadFile(fileName)
		if err != nil {
			http.Error(w, "Could not read data", http.StatusInternalServerError)
			return
		}

		// Parse file as array of gossip objects
		var objects []gossip.Gossip_object
		if err = json.Unmarshal(content, &objects); err != nil {
			http.Error(w, "Could not unmarshal data", http.StatusInternalServerError)
			return
		}

		// If period is specified as a query parameter, then we return the STH corresponding to the
		// requested period, otherwise we return all the STHs stored
		period := r.URL.Query().Get("period")

		// No query parameter given
		if period == "" {
			fmt.Fprint(w, string(content))
			return
		}

		var filteredObjects []gossip.Gossip_object
		for _, obj := range objects {
			if obj.Period == period {
				filteredObjects = append(filteredObjects, obj)
			}
		}

		if len(filteredObjects) == 0 {
			fmt.Fprint(w, filteredObjects)
			return
		}

		content, err = json.MarshalIndent(filteredObjects, "", "    ")
		if err != nil {
			http.Error(w, "Could not marshal response", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, string(content))
	}
}
