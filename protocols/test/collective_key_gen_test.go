package test

import (
	"fmt"
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

func TestCollectiveKeyGeneration(t *testing.T) {

	var nbnodes = []int{3, 8, 16}
	var paramsSets = bfv.DefaultParams
	var storageDirectory = "/tmp/"
	if testing.Short() {
		nbnodes = nbnodes[:1]
		paramsSets = paramsSets[:1]
	}

	log.SetDebugVisible(1)

	for _, params := range paramsSets {
		var lt *utils.LocalTest
		//register the test protocols for each params set
		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("CollectiveKeyGenerationTest-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
				log.Lvl3("new collective key gen protocol instance for", tni.ServerIdentity())
				instance, err := protocols.NewCollectiveKeyGeneration(tni)
				if err != nil {
					return nil, err
				}

				if tni.IsRoot() {
					//Only need to be loaded once par protocol.
					log.Lvl1("Loading once ! ")
					lt, err = utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
					if err != nil {
						return nil, err
					}

				}

				crsGen := dbfv.NewCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
				crp := crsGen.ClockNew()

				e = instance.(*protocols.CollectiveKeyGenerationProtocol).Init(params, lt.SecretKeyShares0[tni.ServerIdentity().ID], crp)
				return
			}); err != nil {
			log.Error("Could not start CollectiveKeyGenerationTest : ", err)
			t.Fail()
		}

		for _, N := range nbnodes {
			t.Run(fmt.Sprintf("/local/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalCKG(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory)
			})

			t.Run(fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalCKG(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory)
			})

		}
	}
}

func testLocalCKG(t *testing.T, params *bfv.Parameters, N int, local *onet.LocalTest, storageDirectory string) {
	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", N)
	defer local.CloseAll()

	_, roster, tree := local.GenTree(N, true)
	lt, err := utils.GetLocalTestForRoster(roster, params, storageDirectory)
	if err != nil {
		t.Fatal(err)
	}

	pi, err := local.CreateProtocol(fmt.Sprintf("CollectiveKeyGenerationTest-%d", params.LogN), tree)
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
	log.Lvl1("**********Collective Key Generated for ", len(ckgp.Roster().List), " nodes.****************")
	log.Lvl1("**********Time elapsed : ", elapsed, "*************")

	encoder := bfv.NewEncoder(params)
	enc := bfv.NewEncryptorFromPk(params, ckgp.Pk)
	dec := bfv.NewDecryptor(params, lt.IdealSecretKey0)
	pt := bfv.NewPlaintext(params)
	ct := enc.EncryptNew(pt)
	ptp := dec.DecryptNew(ct)
	msgp := encoder.DecodeUint(ptp)
	if !utils.Equalslice(pt.Value()[0].Coeffs[0], msgp) {
		t.Fatal("Decryption failed")
	}

	err = lt.TearDown(false)
	if err != nil {
		t.Fatal(err)
	}

	log.Lvl1("Success")
}
