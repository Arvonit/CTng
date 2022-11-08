package main

import (
	"CTng/config"
	"CTng/crypto"
	"CTng/gossip"
	"CTng/monitor"
	// "ctng/testData/fakeCA"
	// "ctng/testData/fakeLogger"
	"fmt"
	"os"
	"strconv"
)

const Port = 8080 // Port all CTng infrastructure will run on
// const StorageDirectory = "/proj/PKIsec/exp/fours/storage"
const StorageDirectory = "./deterlab"

// TODO: Generate crypto

func main() {
	helpText := "Usage: fours <monitor|gossiper|logger|ca> <node_number>"
	argc := len(os.Args)
	if argc < 3 {
		fmt.Println(helpText)
		os.Exit(1)
	}

	component := os.Args[1]
	nodeNumber, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println(os.Args[2], "is not a node number")
		os.Exit(1)
	}

	switch component {
	case "gossiper":
		handleGossiper(nodeNumber)
	case "monitor":
		handleMonitor(nodeNumber)
	// TODO: Fix
	// case "logger":
	// 	fakeLogger.RunFakeLogger(os.Args[2])
	// case "ca":
	// 	fakeCA.RunFakeCA(os.Args[2])
	default:
		fmt.Println(helpText)
		os.Exit(1)
	}
}

func handleGossiper(nodeNumber int) {
	config := makeGossiperConfig(nodeNumber)
	context := makeGossiperContext(&config, nodeNumber)
	// fmt.Printf("%+v\n", config)
	// fmt.Printf("%+v\n", context)
	gossip.StartGossiperServer(&context)

}

func handleMonitor(nodeNumber int) {
	config := makeMonitorConfig(nodeNumber)
	context := makeMonitorContext(&config, nodeNumber)
	// fmt.Printf("%+v\n", config)
	// fmt.Printf("%+v\n", context)
	monitor.StartMonitorServer(&context)
}

func makeGossiperContext(config *config.Gossiper_config, nodeNumber int) gossip.GossiperContext {
	storageDir := fmt.Sprintf("%s/gossiper/%d/", StorageDirectory, nodeNumber)
	context := gossip.GossiperContext{
		Config:           config,
		Storage:          new(gossip.Gossip_Storage),
		Obj_TSS_DB:       new(gossip.Gossip_Object_TSS_DB),
		StorageFile:      "data.json",
		StorageID:        strconv.Itoa(nodeNumber),
		StorageDirectory: storageDir,
	}
	return context
}

func makeMonitorContext(config *config.Monitor_config, nodeNumber int) monitor.MonitorContext {
	storageDir := fmt.Sprintf("%s/monitor/%d/", StorageDirectory, nodeNumber)
	context := monitor.MonitorContext{
		Config:                 config,
		Storage_TEMP:           new(gossip.Gossip_Storage),
		Storage_CONFLICT_POM:   new(gossip.Gossip_Storage),
		Storage_ACCUSATION_POM: new(gossip.Gossip_Storage),
		Storage_STH_FULL:       new(gossip.Gossip_Storage),
		Storage_REV_FULL:       new(gossip.Gossip_Storage),
		StorageID:              strconv.Itoa(nodeNumber),
		StorageDirectory:       storageDir,
	}
	return context
}

func makeGossiperConfig(nodeNumber int) config.Gossiper_config {
	var gossipersURLs []string
	var signerURLs []string
	for i := 1; i <= 4; i++ {
		gossipersURLs = append(gossipersURLs, fmt.Sprintf("gossiper-%d:%d", i, Port))
		signerURLs = append(signerURLs, fmt.Sprintf("logger-%d:%d", i, Port))
		signerURLs = append(signerURLs, fmt.Sprintf("ca-%d:%d", i, Port))
	}
	var connectedGossipers []string
	if nodeNumber == 1 {
		connectedGossipers = []string{fmt.Sprintf("gossiper-2:%d", Port), fmt.Sprintf("gossiper-3:%d", Port)}
	} else if nodeNumber == 2 {
		connectedGossipers = []string{fmt.Sprintf("gossiper-3:%d", Port), fmt.Sprintf("gossiper-4:%d", Port)}
	} else if nodeNumber == 3 {
		connectedGossipers = []string{fmt.Sprintf("gossiper-4:%d", Port), fmt.Sprintf("gossiper-1:%d", Port)}
	} else if nodeNumber == 4 {
		connectedGossipers = []string{fmt.Sprintf("gossiper-1:%d", Port), fmt.Sprintf("gossiper-2:%d", Port)}
	}

	// TODO: Fix
	cryptoDirectory := fmt.Sprintf("testData/gossiperNetworkTest/%d/gossiperCrypto.json", nodeNumber)
	crypto, err := crypto.ReadCryptoConfig(cryptoDirectory)
	if err != nil {
		panic(err)
	}

	public := config.Gossiper_public_config{
		Communiation_delay: 50,
		Max_push_size:      3000,
		Period_interval:    10,
		Expiration_time:    86400,
		MMD:                60,
		MRD:                60,
		Gossiper_URLs:      gossipersURLs,
		Signer_URLs:        signerURLs,
	}
	config := config.Gossiper_config{
		Connected_Gossipers: connectedGossipers,
		Owner_URL:           fmt.Sprintf("monitor-%d:%d", nodeNumber, Port),
		Port:                strconv.Itoa(Port),
		Crypto:              crypto,
		Public:              &public,
	}
	return config
}

func makeMonitorConfig(nodeNumber int) config.Monitor_config {
	var allCAs []string
	var allLoggers []string
	for i := 1; i <= 4; i++ {
		allCAs = append(allCAs, fmt.Sprintf("ca-%d:%d", i, Port))
		allLoggers = append(allLoggers, fmt.Sprintf("logger-%d:%d", i, Port))
	}

	// TODO: Fix
	cryptoDirectory := fmt.Sprintf("testData/gossiperNetworkTest/%d/gossiperCrypto.json", nodeNumber)
	crypto, err := crypto.ReadCryptoConfig(cryptoDirectory)
	if err != nil {
		println("crypto failed")
		panic(err)
	}

	public := config.Monitor_public_config{
		All_CA_URLs:      allCAs,
		All_Logger_URLs:  allLoggers,
		Gossip_wait_time: 1,
		MMD:              60,
		MRD:              60,
		Http_vers:        []string{"2", "1", "3"},
		Length:           64,
	}
	config := config.Monitor_config{
		CA_URLs:      []string{fmt.Sprintf("ca-%d:%d", nodeNumber, Port)},
		Logger_URLs:  []string{fmt.Sprintf("logger-%d:%d", nodeNumber, Port)},
		Gossiper_URL: fmt.Sprintf("monitor-%d:%d", nodeNumber, Port),
		Port:         strconv.Itoa(Port),
		Crypto:       crypto,
		Public:       &public,
	}
	return config
}
