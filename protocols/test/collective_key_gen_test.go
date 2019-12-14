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

var params = bfv.DefaultParams[0]
var nbnodes = 5
var compareKeys = false

//***Go to manager -> assignparametersbeforestart
//***If true then the parameters are assigned before the protocol starts. If False they are assigned on startup. may lead to different performance result.

func TestLocalCollectiveKeyGeneration(t *testing.T) {
	log.SetDebugVisible(1)

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

	log.Lvl1("Starting ckgp")
	now := time.Now()
	err = ckgp.Start()
	defer ckgp.Done()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	ckgp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("**********Collective Key Generated for ", len(ckgp.Roster().List), " nodes.****************")
	log.Lvl1("**********Time elapsed : ", elapsed, "*************")
	if compareKeys {
		log.Lvl1("*******Now comparing all polynomials.")
		CheckKeys(ckgp, err, t)
	}

	log.Lvl1("Success")

}

//same as local except we use TCP.
func TestLocalTCPCollectiveKeyGeneration(t *testing.T) {

	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeyGenerationTestTCP", NewCollectiveKeyGenerationTest); err != nil {
		log.Error("Could not start CollectiveKeyGenerationTest : ", err)

	}

	local := onet.NewTCPTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectiveKeyGenerationTestTCP", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	ckgp := pi.(*protocols.CollectiveKeyGenerationProtocol)
	log.Lvl1("Starting ckgp")
	now := time.Now()
	err = ckgp.Start()

	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	ckgp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("***********Collective Key Generated for ", len(ckgp.Roster().List), " nodes.*********")
	log.Lvl1("*****************Time elapsed : ", elapsed, "*****************")

	//check if we have all the same polys ckg_0
	if compareKeys {
		log.Lvl1("-Now comparing all polynomials.")
		CheckKeys(ckgp, err, t)

	}
	ckgp.Done()

	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	local.CloseAll()
	*/
}

func NewCollectiveKeyGenerationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("New collective key gen test.")
	proto, err := protocols.NewCollectiveKeyGeneration(tni)
	if err != nil {
		return nil, err
	}
	instance := proto.(*protocols.CollectiveKeyGenerationProtocol)
	if protocols.AssignParametersBeforeStart {
		instance.Params = *params
		instance.Sk = *bfv.NewSecretKey(params)
	}

	return instance, nil
}

func CheckKeys(ckgp *protocols.CollectiveKeyGenerationProtocol, err error, t *testing.T) {
	keys := make([]bfv.PublicKey, nbnodes)
	for i := 0; i < nbnodes; i++ {
		//get the keys.

		keys[i] = (<-ckgp.ChannelPublicKey).PublicKey
	}
	for _, k1 := range keys {
		for _, k2 := range keys {
			err = utils.CompareKeys(k1, k2)
			if err != nil {
				log.Error("Error in polynomial comparison : ", err)
				t.Fail()
			}
		}
	}
}
