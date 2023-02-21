package logger_ca


import (
	"CTng/Gen"
	"testing"
)

func TestConfigGeneration(t *testing.T) {
	// Generate the config files for the CAs
	// The parameters are: num_gossiper int, Threshold int, num_logger int, num_ca int, num_cert int, MMD int, MRD int, config_path string
	Gen.Generateall(4,2,2,1,7,60,60,"")
}
