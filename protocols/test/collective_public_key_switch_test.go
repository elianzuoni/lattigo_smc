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

func TestCollectivePublicKeySwitchingLocal(t *testing.T) {
	//***VARIABLES FOR TEST ****/

	var nbnodes = 7
	var SkHash = "sk0"
	var CPKSparams = bfv.DefaultParams[0]
	var VerifyCorrectness = false

	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)

	SkOutput := bfv.NewKeyGenerator(CPKSparams).NewSecretKey()
	publickey := bfv.NewKeyGenerator(CPKSparams).NewPublicKey(SkOutput)

	CipherText := bfv.NewCiphertextRandom(CPKSparams, 1)

	//Inject the parameters for each node
	if _, err := onet.GlobalProtocolRegister("CollectivePublicKeySwitchingTestLocal", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		log.Lvl4("PCKS test protocol")
		proto, err := protocols.NewCollectivePublicKeySwitching(tni)
		if err != nil {
			return nil, err
		}
		sk, err := utils.GetSecretKey(CPKSparams, tni.ServerIdentity().ID)
		if err != nil {
			log.Error("could not get secret key : ", err)
		}
		instance := proto.(*protocols.CollectivePublicKeySwitchingProtocol)
		instance.Params = *CPKSparams
		instance.PublicKey = *publickey
		instance.Ciphertext = *CipherText
		instance.Sk = *sk
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectivePublicKeySwitchingTestLocal", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	pcksp := pi.(*protocols.CollectivePublicKeySwitchingProtocol)

	log.Lvl4("Starting cksp")
	now := time.Now()
	err = pcksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	pcksp.Wait()
	elapsed := time.Since(now)

	log.Lvl1("*************Public Collective key switching done. ************")
	log.Lvl1("*********** Time elaspsed ", elapsed, "***************")
	if VerifyCorrectness {
		CheckCorrectnessPCKS(err, t, tree, SkOutput, CipherText, pcksp, CPKSparams, SkHash)
	}

	pcksp.Done()

	log.Lvl1("Success")

}

func TestCollectivePublicKeySwitchingTCP(t *testing.T) {
	//***VARIABLES FOR TEST ****/

	var nbnodes = 7
	var SkHash = "sk0"
	var CPKSparams = bfv.DefaultParams[0]
	var VerifyCorrectness = false

	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally TCP with nodes amount : ", nbnodes)

	SkOutput := bfv.NewKeyGenerator(CPKSparams).NewSecretKey()
	publickey := bfv.NewKeyGenerator(CPKSparams).NewPublicKey(SkOutput)

	CipherText := bfv.NewCiphertextRandom(CPKSparams, 1)

	//Inject the parameters for each node
	if _, err := onet.GlobalProtocolRegister("CollectivePublicKeySwitchingTestTCP", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		log.Lvl4("PCKS test protocol")
		proto, err := protocols.NewCollectivePublicKeySwitching(tni)
		if err != nil {
			return nil, err
		}
		sk, err := utils.GetSecretKey(CPKSparams, tni.ServerIdentity().ID)
		if err != nil {
			log.Error("could not get secret key : ", err)
		}
		instance := proto.(*protocols.CollectivePublicKeySwitchingProtocol)
		instance.Params = *CPKSparams
		instance.PublicKey = *publickey
		instance.Ciphertext = *CipherText
		instance.Sk = *sk
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	local := onet.NewTCPTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectivePublicKeySwitchingTestTCP", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	pcksp := pi.(*protocols.CollectivePublicKeySwitchingProtocol)

	log.Lvl4("Starting cksp")
	now := time.Now()
	err = pcksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	pcksp.Wait()
	elapsed := time.Since(now)

	log.Lvl1("*************Public Collective key switching done. ************")
	log.Lvl1("*********** Time elaspsed ", elapsed, "***************")
	if VerifyCorrectness {
		CheckCorrectnessPCKS(err, t, tree, SkOutput, CipherText, pcksp, CPKSparams, SkHash)
	}

	pcksp.Done()

	log.Lvl1("Success")

}
