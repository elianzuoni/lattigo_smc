package test

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
	"time"
)

//Global variables to modify tests.

func TestRefreshProtocol(t *testing.T) {
	/**Variables for test ***/
	var nbnodes = 7
	var VerifyCorrectness = false
	var params = bfv.DefaultParams[0]
	var SkInputHash = "sk0"

	log.SetDebugVisible(1)

	log.Lvl1("Setting up context and plaintext/ciphertext of reference")

	CipherText := bfv.NewCiphertextRandom(params, 1)

	crp := dbfv.NewCRPGenerator(params, nil)
	crp.Seed([]byte{})
	crs := *crp.ClockNew() //crp.ClockNew() is not thread safe ?

	log.Lvl1("Set up done - Starting protocols")
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveRefreshKeyTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		proto, err := protocols.NewCollectiveRefresh(tni)
		if err != nil {
			return nil, err
		}
		SkInput, err := utils.GetSecretKey(params, SkInputHash+tni.ServerIdentity().String())
		if err != nil {
			return nil, err
		}

		instance := proto.(*protocols.RefreshKeyProtocol)
		instance.Ciphertext = *CipherText
		instance.CRS = crs
		instance.Sk = *SkInput
		instance.Params = *params
		return instance, nil

	}); err != nil {
		log.Error("Could not start RefreshKeyTest : ", err)
		t.Fail()

	}

	//can start protocol
	log.Lvl1("Started to test refresh key locally with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)
	pi, err := local.CreateProtocol("CollectiveRefreshKeyTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	rkp := pi.(*protocols.RefreshKeyProtocol)
	now := time.Now()
	log.Lvl4("Starting rkp")
	err = rkp.Start()

	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	rkp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("*****************Refresh key done.******************")
	log.Lvl1("*****************Time elapsed : ", elapsed, "*******************")

	//From here check that Original ciphertext decrypted under SkInput === Resulting ciphertext decrypted under SkOutput
	if VerifyCorrectness {
		CheckCorrectnessRefresh(err, t, local, CipherText, rkp, SkInputHash, params)
	}
	rkp.Done()

	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Test over.")
	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	//local.CloseAll()
	*/

}
