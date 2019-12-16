package test

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
	"time"
)

var params = bfv.DefaultParams[0]

//***Go to manager -> assignparametersbeforestart
//***If true then the parameters are assigned before the protocol starts. If False they are assigned on startup. may lead to different performance result.

func TestCollectiveKeyGeneration(t *testing.T) {
	/***VARIABLES TO USE FOR TH TEST ********/
	var nbnodes = 5

	log.SetDebugVisible(1)

	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeyGenerationTest", newCollectiveKeyGenerationTest); err != nil {
		log.Error("Could not start CollectiveKeyGenerationTest : ", err)
		t.Fail()
	}

	t.Run(fmt.Sprintf("/local/nbnodes=%d", nbnodes), func(t *testing.T) {
		testLocal(t, nbnodes, onet.NewLocalTest(suites.MustFind("Ed25519")))
	})

	t.Run(fmt.Sprintf("/TCP/nbnodes=%d", nbnodes), func(t *testing.T) {
		testLocal(t, nbnodes, onet.NewTCPTest(suites.MustFind("Ed25519")))
	})

}

func testLocal(t *testing.T, nbnodes int, local *onet.LocalTest) {
	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	rq, err := ring.NewContextWithParams(1 << params.LogN, params.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	isk := bfv.NewSecretKey(params) // ideal secret key
	for _, tn := range tree.List() {
		ski, err := utils.GetSecretKey(params, fmt.Sprint("sk-party-",tn.RosterIndex))
		if err != nil {
			t.Fatal(err)
		}
		rq.Add(isk.Get(), ski.Get(), isk.Get())
	}

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

	enc := bfv.NewEncryptorFromPk(params,  ckgp.Pk)
	dec := bfv.NewDecryptor(params, isk)
	pt := bfv.NewPlaintext(params)
	ct := enc.EncryptNew(pt)
	ptp := dec.DecryptNew(ct)
	if !utils.Equalslice(pt.Value()[0].Coeffs[0], ptp.Value()[0].Coeffs[0]) {
		t.Fatal("Decryption failed")
	}

	log.Lvl1("Success")

}

func newCollectiveKeyGenerationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("new collective key gen protocol instance for", tni.ServerIdentity())
	proto, err := protocols.NewCollectiveKeyGeneration(tni)
	if err != nil {
		return nil, err
	}
	sk, err := utils.GetSecretKey(params, fmt.Sprint("sk-party-",tni.TreeNode().RosterIndex))
	if err != nil {
		return nil, err
	}

	instance := proto.(*protocols.CollectiveKeyGenerationProtocol)
	err = instance.Init(params, sk, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})

	return instance, err
}
