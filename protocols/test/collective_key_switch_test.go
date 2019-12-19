package test

import (
	"fmt"
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

func TestCollectiveKeySwitching(t *testing.T) {
	var nbnodes = []int{3, 8, 16}
	var paramsSets = bfv.DefaultParams
	var storageDirectory = "tmp/"
	if testing.Short() {
		nbnodes = nbnodes[:1]
		paramsSets = paramsSets[:1]
	}

	log.SetDebugVisible(1)

	for _, params := range paramsSets {
		//register protocol for each paramset.
		pt := bfv.NewPlaintext(params)
		var cipher bfv.Ciphertext

		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("CollectiveKeySwitchingTest-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
				log.Lvl3("New Collective key switching instance for ", tni.ServerIdentity())
				instance, err := protocols.NewCollectiveKeySwitching(tni)
				if err != nil {
					return nil, err

				}
				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
				if err != nil {
					return nil, err
				}
				if tni.IsRoot() {
					enc0 := bfv.NewEncryptorFromSk(params, lt.IdealSecretKey0)

					cipher = *enc0.EncryptNew(pt)
				}

				err = instance.(*protocols.CollectiveKeySwitchingProtocol).Init(params, lt.SecretKeyShares0[tni.ServerIdentity().ID], lt.SecretKeyShares1[tni.ServerIdentity().ID], &cipher)

				return instance, err
			}); err != nil {
			log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		}

		//Now run the tests.
		for _, N := range nbnodes {
			t.Run(fmt.Sprintf("/local/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalCKS(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory, pt)
			})
			t.Run(fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalCKS(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory, pt)
			})
		}
	}

}

func testLocalCKS(t *testing.T, params *bfv.Parameters, N int, local *onet.LocalTest, storageDirectory string, plaintext *bfv.Plaintext) {
	log.Lvl1("Starting to test Collective key switching with nodes amount : ", N)
	defer local.CloseAll()

	_, roster, tree := local.GenTree(N, true)
	lt, err := utils.GetLocalTestForRoster(roster, params, storageDirectory)
	defer func() {
		err = lt.TearDown()
		if err != nil {
			t.Fatal(err)
		}
	}()

	if err != nil {
		t.Fatal(err)
	}
	pi, err := local.CreateProtocol(fmt.Sprintf("CollectiveKeySwitchingTest-%d", params.LogN), tree)
	if err != nil {
		t.Fatal("Couldn't create new node : ", err)
	}

	cksp := pi.(*protocols.CollectiveKeySwitchingProtocol)
	log.Lvl1("Starting Cks")
	now := time.Now()
	err = cksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	cksp.Wait()

	elapsed := time.Since(now)
	log.Lvl1("*****************Collective key switching done.******************")
	log.Lvl1("*****************Time elapsed : ", elapsed, "*******************")

	//now check if okay.

	encoder := bfv.NewEncoder(params)
	Decryptor1 := bfv.NewDecryptor(params, lt.IdealSecretKey1)

	//expected
	expected := encoder.DecodeUint(plaintext)
	decoded := encoder.DecodeUint(Decryptor1.DecryptNew(cksp.CiphertextOut))
	log.Lvl1("Exp :", expected[0:25])
	log.Lvl1("Got :", decoded[0:25])
	if !utils.Equalslice(expected, decoded) {
		t.Fatal("Decryption failed")

	}

	log.Lvl1("Success")

}
