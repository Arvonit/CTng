package network

import (
	"CTng/Gen"
	"CTng/gossip"
	"CTng/util"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"testing"
)

func testConfigGeneration(t *testing.T) {
	// Generate the config files for the CAs
	// The parameters are: num_gossiper int, Threshold int, num_logger int, num_ca int, num_cert int, MMD int, MRD int, config_path string
	Gen.Generateall(4, 2, 3, 3, 1, 60, 60, "")
}

func testgossipobjectnum(entry gossip.GossiperLogEntry, Periodoffset int) {
	cumulative := 3 + 3*Periodoffset
	if entry.Num_sth != 3 {
		fmt.Println("Number of unique NUM_POMs is ", entry.Num_sth, "but should be 3.")
	}
	if entry.Num_sth_frag != 12 {
		fmt.Println("Number of NUM_FRAG is ", entry.Num_sth_frag, "but should be 12.")
	}
	if entry.Num_STH_FULL != cumulative {
		fmt.Println("Number of NUM_FULL is ", entry.Num_STH_FULL, "but should be ", cumulative, ".")
	}
	if entry.Num_rev != 3 {
		fmt.Println("Number of REV_FULL is ", entry.Num_STH_FULL, "but should be 3.")
	}
	if entry.Num_rev_frag != 12 {
		fmt.Println("Number of REV_FRAG is ", entry.Num_rev_frag, "but should be 12.")
	}
	if entry.Num_REV_FULL != cumulative {
		fmt.Println("Number of REV_FULL is ", entry.Num_REV_FULL, "but should be ", cumulative, ".")
	}
}

func testfirstglogentry(entry gossip.GossiperLogEntry) {
	if entry.Num_NUM != 0 {
		fmt.Println("Number of unique NOM_POMs is ", entry.Num_NUM, "but should be 0.")
	}
	if entry.Num_NUM_FRAG != 0 {
		fmt.Println("Number of NUM_FRAG is ", entry.Num_NUM_FRAG, "but should be 0.")
	}
	testgossipobjectnum(entry, 0)
}
func testotherglogentry(entry gossip.GossiperLogEntry, Periodoffset int) {
	if entry.Num_NUM != 1 {
		// if number of unique NUM_POMs is not 1, then some monitors are cheating
		fmt.Println("Number of unique NUM_POMs is", entry.Num_NUM, "but should be 1. note: if number of unique NUM_POMs is not 1, then at least one monitor is cheating")
	}
	if entry.Num_NUM_FRAG != 2 {
		fmt.Println("Num_NUM_FRAG is ", entry.Num_NUM_FRAG, "but should be 2.")
	}
	testgossipobjectnum(entry, Periodoffset)
}
func TestGMResult(t *testing.T) {
	//read from /gossiper_testdata/$storage_ID$/gossiper_testdata.json
	var gossiper_log_database [][]gossip.GossiperLogEntry
	for i := 1; i <= 4; i++ {
		var gossiper_log_map_1 gossip.Gossiper_log
		bytedata, _ := util.ReadByte("gossiper_testdata/" + strconv.Itoa(i) + "/gossiper_testdata.json")
		json.Unmarshal(bytedata, &gossiper_log_map_1)
		//iterate through the gossiper_log_map_1, add to a list
		var gossiper_log_map_1_list []gossip.GossiperLogEntry
		for _, v := range gossiper_log_map_1 {
			gossiper_log_map_1_list = append(gossiper_log_map_1_list, v)
			// sort the list by GossiperLogEntry.Period
			sort.Slice(gossiper_log_map_1_list, func(i, j int) bool {
				return gossiper_log_map_1_list[i].Period < gossiper_log_map_1_list[j].Period
			})
		}
		gossiper_log_database = append(gossiper_log_database, gossiper_log_map_1_list)
	}
	for i, gossiper_log_map_1_list := range gossiper_log_database {
		fmt.Println("Start testing gossiper ", i+1)
		//fmt.Println(gossiper_log_map_1_list)
		testfirstglogentry(gossiper_log_map_1_list[0])
		//test other entries
		for i := 1; i < len(gossiper_log_map_1_list); i++ {
			testotherglogentry(gossiper_log_map_1_list[i], i)
		}
	}
}
