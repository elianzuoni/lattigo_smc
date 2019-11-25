package test

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
	"time"
)

func TestLocalCollectiveKeyGeneration(t *testing.T) {
	nbnodes := 3
	log.SetDebugVisible(4)

	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeyGenerationTest", NewCollectiveKeyGenerationTest); err != nil {
		log.Error("Could not start CollectiveKeyGenerationTest : ", err)
		t.Fail()

	}

	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectiveKeyGenerationTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	ckgp := pi.(*protocols.CollectiveKeyGenerationProtocol)
	//ckgp.Params = bfv.DefaultParams[0]
	log.Lvl1("Starting ckgp")
	err = ckgp.Start()
	defer ckgp.Done()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	log.Lvl1("Collective Key Generated for ", len(ckgp.Roster().List), " nodes.\n\tNow comparing all polynomials.")

	//check if we have all the same polys ckg_0

	<-time.After(2 * time.Second)
	CheckKeys(ckgp.List(), err, t)

	log.Lvl1("Success")

}

func NewCollectiveKeyGenerationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1("PING")
	proto, err := protocols.NewCollectiveKeyGeneration(tni)
	if err != nil {
		return nil, err
	}
	instance := proto.(*protocols.CollectiveKeyGenerationProtocol)
	instance.Params = bfv.DefaultParams[0]
	return instance, nil
}

func CheckKeys(tree []*onet.TreeNode, err error, t *testing.T) {
	keys := make([]bfv.PublicKey, len(tree))
	ctx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	for i := 0; i < len(tree); i++ {
		//get the keys.
		seed := (tree)[i].ServerIdentity.String()

		key, _ := utils.LoadPublicKey(ctx, seed)
		keys[i] = *key
	}
	for _, k1 := range keys {
		for _, k2 := range keys {
			err := utils.CompareKeys(k1, k2)
			if err != nil {
				log.Error("Error in polynomial comparison : ", err)
				t.Fail()
			}
		}
	}
}

//same as local except we use TCP.
func TestLocalTCPCollectiveKeyGeneration(t *testing.T) {

	nbnodes := 3
	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	local := onet.NewTCPTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectiveKeyGeneration", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	ckgp := pi.(*protocols.CollectiveKeyGenerationProtocol)
	ckgp.Params = bfv.DefaultParams[0]
	log.Lvl1("Starting ckgp")
	err = ckgp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	log.Lvl1("Collective Key Generated for ", len(ckgp.Roster().List), " nodes.\n\tNow comparing all polynomials.")
	<-time.After(time.Second) // Leave some time for children to terminate

	//check if we have all the same polys ckg_0
	CheckKeys(ckgp.List(), err, t)

	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	//local.CloseAll()
	*/
}
