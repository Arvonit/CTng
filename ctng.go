package main

/*
Code Ownership:
Finn - Made main function
*/
import (
	"CTng/client"
	"CTng/logger_ca"
	"CTng/miniclient"
	"CTng/network"
	"CTng/webserver"
	"CTng/monitor"
	"fmt"
	"os"
)

// main is run when the user types "go run ."
// it allows a user to run a gossiper, monitor, fakeLogger, or fakeCA.
// Currently unimplemented: Different object_storage locations than ./gossiper_data.json and ./monitor_data.json
// This field could be defined within the configuration files to make this more modular.
func main() {
	helpText := "Usage:\n ./CTng [gossiper|monitor] <public_config_file_path> <private_config_file_path> <crypto_config_path>\n ./Ctng [logger|ca] <fakeentity_config_path>\n ./CTng web"

	if len(os.Args) < 2 {
		fmt.Println(helpText)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "minilogger":
		logger_ca.StartLogger(os.Args[2])
	case "minica":
		logger_ca.StartCA()
	case "lcmonitor":
		logger_ca.StartMonitor()
	case "web":
		webserver.Start()
	case "minimon":
		monitor.StartMinimon()
	case "miniclient":
		miniclient.Start()
	case "network_monitor":
		network.StartMonitor(os.Args[2])
	case "network_gossiper":
		network.StartGossiper(os.Args[2])
	case "network_logger":
		network.StartLogger(os.Args[2])
	case "network_ca":
		network.StartCA(os.Args[2])
	case "client":
		ctx := client.InitializeClientContext(os.Args[2], os.Args[3])
		client.StartClientServer(&ctx)
	default:
		fmt.Println(helpText)
	}
}
