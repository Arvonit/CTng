package gossip

import (
	"CTng/crypto"
	"encoding/json"
	"net/http"
	"sync"
)

// Content tbs = NUM_ACC_FULL || NUM_CON_FULL || PERIOD || SIGNER_MONITOR
// Content tbs is the same for all NUM types
type NUM struct {
	NUM_ACC_FULL   string
	NUM_CON_FULL   string
	Period         string
	Signer_Monitor string
	Crypto_Scheme  string
	Signature      string
}

// Content tbs = NUM_ACC_FULL || NUM_CON_FULL || PERIOD
type NUM_FRAG struct {
	NUM_ACC_FULL    string
	NUM_CON_FULL    string
	Period          string
	Signer_Gossiper string
	Crypto_Scheme   string
	Signature       string
}

type NUM_FULL struct {
	NUM_ACC_FULL  string
	NUM_CON_FULL  string
	Period        string
	Signers       map[int]string
	Crypto_Scheme string
	Signature     string
}

type NUM_Counter struct {
	NUMs      map[string][]string
	NUM_FRAGs []*NUM_FRAG
	NUM_FULL  bool
	NUMs_lock sync.Mutex
}

func NUM_Counter_Init() *NUM_Counter {
	return &NUM_Counter{
		NUMs:      make(map[string][]string),
		NUM_FRAGs: make([]*NUM_FRAG, 0),
		NUM_FULL:  false,
	}
}

func (n *NUM_Counter) Add_NUM(num any) {
	n.NUMs_lock.Lock()
	defer n.NUMs_lock.Unlock()
	var key string
	switch num.(type) {
	case *NUM:
		key = num.(*NUM).NUM_ACC_FULL + num.(*NUM).NUM_CON_FULL + num.(*NUM).Period
		if _, ok := n.NUMs[key]; !ok {
			n.NUMs[key] = []string{}
		}
		n.NUMs[key] = append(n.NUMs[key], num.(*NUM).Signer_Monitor)
	case *NUM_FRAG:
		n.NUM_FRAGs = append(n.NUM_FRAGs, num.(*NUM_FRAG))
	case *NUM_FULL:
		n.NUM_FULL = true
	}

}

func (n *NUM_Counter) Get_NUM(num any) int {
	n.NUMs_lock.Lock()
	defer n.NUMs_lock.Unlock()
	switch num.(type) {
	case *NUM:
		return len(n.NUMs[num.(*NUM).NUM_ACC_FULL+num.(*NUM).NUM_CON_FULL+num.(*NUM).Period])
	case *NUM_FRAG:
		return len(n.NUM_FRAGs)
	}
	return 0
}

func (n *NUM_Counter) Clear() {
	n.NUMs_lock.Lock()
	defer n.NUMs_lock.Unlock()
	n.NUMs = make(map[string][]string)
	n.NUM_FRAGs = []*NUM_FRAG{}
	n.NUM_FULL = false
}

func (n *NUM) Verify(cryptoconf *crypto.CryptoConfig) error {
	// Verify that the signature is valid
	sig, _ := crypto.RSASigFromString(n.Signature)
	return cryptoconf.Verify([]byte(n.NUM_ACC_FULL+n.NUM_CON_FULL+n.Period+n.Signer_Monitor), sig)
}

func (n *NUM_FRAG) Verify(cryptoconf *crypto.CryptoConfig) error {
	// Verify that the signature is valid
	sig, _ := crypto.SigFragmentFromString(n.Signature)
	return cryptoconf.FragmentVerify(n.NUM_ACC_FULL+n.NUM_CON_FULL+n.Period, sig)
}

func (n *NUM_FULL) Verify(cryptoconf *crypto.CryptoConfig) error {
	// Verify that the signature is valid
	sig, _ := crypto.ThresholdSigFromString(n.Signature)
	return cryptoconf.ThresholdVerify(n.NUM_ACC_FULL+n.NUM_CON_FULL+n.Period, sig)
}

// generate NUM wil be a montior function

// generate NUM_FRAG wil be a gossiper function
func Generate_NUM_FRAG(n *NUM, cryptoconf *crypto.CryptoConfig) *NUM_FRAG {
	// Generate a signature fragment
	sig, _ := cryptoconf.ThresholdSign(n.NUM_ACC_FULL + n.NUM_CON_FULL + n.Period)
	return &NUM_FRAG{
		NUM_ACC_FULL:    n.NUM_ACC_FULL,
		NUM_CON_FULL:    n.NUM_CON_FULL,
		Period:          n.Period,
		Signer_Gossiper: cryptoconf.SelfID.String(),
		Crypto_Scheme:   "bls",
		Signature:       sig.String(),
	}
}

// when calling this function, we assume that every entry in NUM_FRAG_LIST have the same NUM_ACC_FULL, NUM_CON_FULL, Period, Signer_Monitor, Crypto_Scheme
func Generate_NUM_FULL(NUM_FRAG_LIST []*NUM_FRAG, cryptoconf *crypto.CryptoConfig) *NUM_FULL {
	partial_sigs := make([]crypto.SigFragment, len(NUM_FRAG_LIST))
	for i, num_frag := range NUM_FRAG_LIST {
		partial_sigs[i], _ = crypto.SigFragmentFromString(num_frag.Signature)
	}
	TSS_Sig, _ := cryptoconf.ThresholdAggregate(partial_sigs)
	TSS_sig_string, _ := TSS_Sig.String()
	signermap := make(map[int]string)
	for i := 0; i < len(NUM_FRAG_LIST); i++ {
		signermap[i] = NUM_FRAG_LIST[i].Signer_Gossiper
	}
	return &NUM_FULL{
		NUM_ACC_FULL:  NUM_FRAG_LIST[0].NUM_ACC_FULL,
		NUM_CON_FULL:  NUM_FRAG_LIST[0].NUM_CON_FULL,
		Period:        NUM_FRAG_LIST[0].Period,
		Signers:       signermap,
		Crypto_Scheme: "bls",
		Signature:     TSS_sig_string,
	}
}

func IsDuplicateNUM(c GossiperContext, num any) bool {
	//Lock
	c.NUM_Storage.NUMs_lock.Lock()
	defer c.NUM_Storage.NUMs_lock.Unlock()
	switch num.(type) {
	case *NUM:
		// check if the num is in the NUM_Storage
		// if yes, return true
		// if no, return false
		// if Signer_Monitor is in the NUM_Storage, return true
		// if not, return false
		if len(c.NUM_Storage.NUMs[num.(*NUM).NUM_ACC_FULL+num.(*NUM).NUM_CON_FULL+num.(*NUM).Period]) > 0 {
			// check if the signer is in the NUM_Storage
			for _, signer := range c.NUM_Storage.NUMs[num.(*NUM).NUM_ACC_FULL+num.(*NUM).NUM_CON_FULL+num.(*NUM).Period] {
				if signer == num.(*NUM).Signer_Monitor {
					return true
				}
			}
			return false
		}
		return false
	case *NUM_FRAG:
		// check if the num_frag is in the NUM_Storage
		// if yes, return true
		// if no, return false
		if len(c.NUM_Storage.NUM_FRAGs) > 0 {
			for _, num_frag := range c.NUM_Storage.NUM_FRAGs {
				if num_frag.Signature == num.(*NUM_FRAG).Signature {
					return true
				}
			}
			return false
		}
		return false
	case *NUM_FULL:
		// check if the num_full is in the NUM_Storage
		if c.NUM_Storage.NUM_FULL {
			return true
		}
		return false
	}
	return false
}

func Need_More_NUM_FRAG(c GossiperContext) bool {
	c.NUM_Storage.NUMs_lock.Lock()
	if len(c.NUM_Storage.NUM_FRAGs) < c.Config.Crypto.Threshold {
		c.NUM_Storage.NUMs_lock.Unlock()
		return true
	}
	c.NUM_Storage.NUMs_lock.Unlock()
	return false
}
func handleNUM(g *GossiperContext, w http.ResponseWriter, r *http.Request) {
	// get the num from the request
	decoder := json.NewDecoder(r.Body)
	var num NUM
	err := decoder.Decode(&num)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// check if the num is duplicate
	if IsDuplicateNUM(*g, &num) {
		return
	}
	// check if there are threshold number of num_frags already
	if !Need_More_NUM_FRAG(*g) {
		return
	}
	// verify the num
	err = num.Verify(g.Config.Crypto)
	if err != nil {
		panic(err)
	}
	g.NUM_Storage.Add_NUM(&num)
	Gossip_NUM_type(*g, &num)
	if g.NUM_Storage.Get_NUM(&num) >= g.Config.Crypto.Threshold {
		// generate NUM_FRAG
		num_frag := Generate_NUM_FRAG(&num, g.Config.Crypto)
		// send NUM_FRAG to all gossiper
		Gossip_NUM_type(*g, num_frag)
		if !IsDuplicateNUM(*g, num_frag) && Need_More_NUM_FRAG(*g) {
			g.NUM_Storage.Add_NUM(num_frag)
			if g.NUM_Storage.Get_NUM(num_frag) >= g.Config.Crypto.Threshold {
				// generate NUM_FULL
				num_full := Generate_NUM_FULL(g.NUM_Storage.NUM_FRAGs, g.Config.Crypto)
				// send NUM_FULL to all gossiper
				Gossip_NUM_type(*g, num_full)
				if !IsDuplicateNUM(*g, num_full) {
					g.NUM_Storage.Add_NUM(num_full)
					g.NUM_Storage.NUM_FULL = true
					// send NUM_FULL to the monitor
					Gossip_NUM_type(*g, num_full)
				}
			}
		}
	}
}

func handleNUM_FRAG(g *GossiperContext, w http.ResponseWriter, r *http.Request) {
	// get the num_frag from the request
	decoder := json.NewDecoder(r.Body)
	var num_frag NUM_FRAG
	err := decoder.Decode(&num_frag)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// check if the num_frag is duplicate
	if IsDuplicateNUM(*g, &num_frag) {
		return
	}
	// check if there are threshold number of num_frags already
	if !Need_More_NUM_FRAG(*g) {
		return
	}
	// check if the NUM_FULL is already present
	if g.NUM_Storage.NUM_FULL {
		return
	}
	// verify the num_frag
	err = num_frag.Verify(g.Config.Crypto)
	if err != nil {
		panic(err)
	}
	g.NUM_Storage.Add_NUM(&num_frag)
	if g.NUM_Storage.Get_NUM(&num_frag) == g.Config.Crypto.Threshold {
		// generate NUM_FULL
		num_full := Generate_NUM_FULL(g.NUM_Storage.NUM_FRAGs, g.Config.Crypto)
		// send NUM_FULL to all monitor
		g.NUM_Storage.NUM_FULL = true
		SendToOwner(g, *num_full)
		Gossip_NUM_type(*g, num_full)
	}
}

func handleNUM_FULL(g *GossiperContext, w http.ResponseWriter, r *http.Request) {
	// get the num_full from the request
	decoder := json.NewDecoder(r.Body)
	var num_full NUM_FULL
	err := decoder.Decode(&num_full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// check if the num_full is duplicate
	if IsDuplicateNUM(*g, &num_full) {
		return
	}
	// verify the num_full
	err = num_full.Verify(g.Config.Crypto)
	if err != nil {
		panic(err)
	}
	// if NUM_FULL in NUM_Storage is empty, then send it to owner
	if !g.NUM_Storage.NUM_FULL {
		// send NUM_FULL to owner
		g.NUM_Storage.NUM_FULL = true
		SendToOwner(g, num_full)
	}
}
