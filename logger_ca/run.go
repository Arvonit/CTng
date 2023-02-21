package logger_ca

import (
	"CTng/CA"
	"CTng/Logger"
)

func StartCA(){
	path_prefix := "logger_ca/ca_testconfig/1"
	path_1 :=  path_prefix  + "/CA_public_config.json"
	path_2 :=  path_prefix  + "/CA_private_config.json"
	path_3 :=  path_prefix  + "/CA_crypto_config.json"
	path_4 := "logger_ca/ca_testdata.json"
	ctx_ca_1 :=  CA.InitializeCAContext(path_1,path_2,path_3)
	ctx_ca_1.StoragePath = path_4
	CA.StartCA(ctx_ca_1)
}

func StartLogger(LID string){
	path_prefix := "logger_ca/logger_testconfig/"+LID
	path_1 :=  path_prefix+ "/Logger_public_config.json"
	path_2 :=  path_prefix+ "/Logger_private_config.json"
	path_3 :=  path_prefix+ "/Logger_crypto_config.json"
	ctx_logger_1 := Logger.InitializeLoggerContext(path_1,path_2,path_3)
	Logger.StartLogger(ctx_logger_1)
}