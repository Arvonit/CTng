package testData

import (
	"CTng/Gen"
	"testing"
)

/*
import(
	"CTng/CA"
	"CTng/Logger"
	"CTng/monitor"
	"CTng/gossip"
	"CTng/testserver"
	//"CTng/config"
	"CTng/crypto"
	"testing"
	//"sync"
	"fmt"
	"time"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"encoding/pem"
	"log"
	"crypto/rand"
	"github.com/bits-and-blooms/bitset"
)

var ctx_ca_1 *CA.CAContext
var ctx_ca_2 *CA.CAContext
var ctx_logger_1 *Logger.LoggerContext
var ctx_logger_2 *Logger.LoggerContext
var ctx_monitor_1 *monitor.MonitorContext
var ctx_monitor_2 *monitor.MonitorContext
var ctx_monitor_3 *monitor.MonitorContext
var ctx_monitor_4 *monitor.MonitorContext
var ctx_gossiper_1 *gossip.GossiperContext
var ctx_gossiper_2 *gossip.GossiperContext
var ctx_gossiper_3 *gossip.GossiperContext
var ctx_gossiper_4 *gossip.GossiperContext


func TestContextinit(t *testing.T){
	ctx_ca_1 = InitializeOneEntity("CA","1").(*CA.CAContext)
	ctx_ca_2 = InitializeOneEntity("CA","2").(*CA.CAContext)
	ctx_logger_1 = InitializeOneEntity("Logger","1").(*Logger.LoggerContext)
	ctx_logger_2 = InitializeOneEntity("Logger","2").(*Logger.LoggerContext)
	ctx_monitor_1 = InitializeOneEntity("Monitor","1").(*monitor.MonitorContext)
	ctx_monitor_2 = InitializeOneEntity("Monitor","2").(*monitor.MonitorContext)
	ctx_monitor_3 = InitializeOneEntity("Monitor","3").(*monitor.MonitorContext)
	ctx_monitor_4 = InitializeOneEntity("Monitor","4").(*monitor.MonitorContext)
	ctx_gossiper_1 = InitializeOneEntity("Gossiper","1").(*gossip.GossiperContext)
	ctx_gossiper_2 = InitializeOneEntity("Gossiper","2").(*gossip.GossiperContext)
	ctx_gossiper_3 = InitializeOneEntity("Gossiper","3").(*gossip.GossiperContext)
	ctx_gossiper_4 = InitializeOneEntity("Gossiper","4").(*gossip.GossiperContext)
	fmt.Println(ctx_ca_1.CA_private_config.Signer, ctx_ca_2.CA_private_config.Signer)
	fmt.Println(ctx_logger_1.Logger_private_config.Signer, ctx_logger_2.Logger_private_config.Signer)
	fmt.Println(ctx_monitor_1.Monitor_private_config.Signer, ctx_monitor_2.Monitor_private_config.Signer)
	fmt.Println(ctx_monitor_3.Monitor_private_config.Signer, ctx_monitor_4.Monitor_private_config.Signer)
	fmt.Println(ctx_gossiper_1.Gossiper_private_config.Signer, ctx_gossiper_2.Gossiper_private_config.Signer)
	fmt.Println(ctx_gossiper_3.Gossiper_private_config.Signer, ctx_gossiper_4.Gossiper_private_config.Signer)
}
*/

func TestGenerateall(t *testing.T) {
	Gen.Generateall(4, 2, 1, 1, 1, 60, 60, "")
}
