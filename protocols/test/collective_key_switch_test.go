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

//Global variables to modify tests.

func TestCollectiveSwitchingLocal(t *testing.T) {
	/**VARIABLES FOR TEST**/
	var nbnodes = 7
	var VerifyCorrectness = false
	var params = (bfv.DefaultParams[0])

	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)

	log.Lvl1("Setting up context and plaintext/ciphertext of reference")

	CipherText := bfv.NewCiphertextRandom(params, 1)
	log.Lvl1("Set up done - Starting protocols")
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeySwitchingTestLocal", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		proto, err := protocols.NewCollectiveKeySwitching(tni)
		if err != nil {
			return nil, err
		}
		SkInput, err := utils.GetSecretKey(params, tni.ServerIdentity().ID)
		if err != nil {
			return nil, err
		}
		SkOutput, err := utils.GetSecretKey(params, tni.ServerIdentity().ID)
		if err != nil {
			return nil, err
		}
		instance := proto.(*protocols.CollectiveKeySwitchingProtocol)
		instance.Params = protocols.SwitchingParameters{
			Params:     *params,
			SkInput:    *SkInput,
			SkOutput:   *SkOutput,
			Ciphertext: *CipherText,
		}
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	//can start protocol
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)
	pi, err := local.CreateProtocol("CollectiveKeySwitchingTestLocal", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*protocols.CollectiveKeySwitchingProtocol)
	now := time.Now()
	log.Lvl4("Starting cksp")
	err = cksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	cksp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("*****************Collective key switching done.******************")
	log.Lvl1("*****************Time elapsed : ", elapsed, "*******************")

	//From here check that Original ciphertext decrypted under SkInput === Resulting ciphertext decrypted under SkOutput
	if VerifyCorrectness {
		CheckCorrectnessCKS(err, t, local, CipherText, cksp, params)
	}

	cksp.Done()
	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Success")

}

func TestCollectiveSwitchingTCP(t *testing.T) {
	/**VARIABLES FOR TEST **/
	var nbnodes = 7
	var VerifyCorrectness = false
	var params = (bfv.DefaultParams[0])

	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)

	log.Lvl1("Setting up context and plaintext/ciphertext of reference")

	CipherText := bfv.NewCiphertextRandom(params, 1)
	log.Lvl1("Set up done - Starting protocols")
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeySwitchingTestTCP", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		proto, err := protocols.NewCollectiveKeySwitching(tni)
		if err != nil {
			return nil, err
		}
		SkInput, err := utils.GetSecretKey(params, tni.ServerIdentity().ID)
		if err != nil {
			return nil, err
		}
		SkOutput, err := utils.GetSecretKey(params, tni.ServerIdentity().ID)
		if err != nil {
			return nil, err
		}
		instance := proto.(*protocols.CollectiveKeySwitchingProtocol)
		instance.Params = protocols.SwitchingParameters{
			Params:     *params,
			SkInput:    *SkInput,
			SkOutput:   *SkOutput,
			Ciphertext: *CipherText,
		}
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	//can start protocol
	log.Lvl1("Started to test collective key switching locally TCP with nodes amount : ", nbnodes)
	local := onet.NewTCPTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)
	pi, err := local.CreateProtocol("CollectiveKeySwitchingTestTCP", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*protocols.CollectiveKeySwitchingProtocol)
	now := time.Now()
	log.Lvl4("Starting cksp")
	err = cksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	cksp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("*****************Collective key switching done.******************")
	log.Lvl1("*****************Time elapsed : ", elapsed, "*******************")

	//From here check that Original ciphertext decrypted under SkInput === Resulting ciphertext decrypted under SkOutput
	if VerifyCorrectness {
		CheckCorrectnessCKS(err, t, local, CipherText, cksp, params)
	}

	cksp.Done()
	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Success")

}
