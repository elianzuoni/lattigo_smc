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

//Global variables to modify tests.

func TestRefreshProtocol(t *testing.T) {
	/**Variables for test ***/
	var nbnodes = []int{3, 8, 16}
	var paramsSets = bfv.DefaultParams

	var storageDirectory = "/tmp/"
	if testing.Short() {
		nbnodes = nbnodes[:1]
		paramsSets = paramsSets[:1]
	}

	log.SetDebugVisible(1)

	for _, params := range paramsSets {
		plaintext := bfv.NewPlaintext(params)
		var ciphertext bfv.Ciphertext
		//register the test protocols for each params set
		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("CollectiveRefreshTest-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
				log.Lvl3("new collective refresh protocol instance for", tni.ServerIdentity())
				instance, err := protocols.NewCollectiveRefresh(tni)
				if err != nil {
					return nil, err
				}

				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)

				if err != nil {
					return nil, err
				}

				if tni.IsRoot() {
					ciphertext = *bfv.NewEncryptorFromSk(params, lt.IdealSecretKey0).EncryptNew(plaintext)
				}
				crsGen := dbfv.NewCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
				crp := crsGen.ClockNew()

				e = instance.(*protocols.RefreshProtocol).Init(*params, lt.SecretKeyShares0[tni.ServerIdentity().ID], ciphertext, *crp)
				return
			}); err != nil {
			log.Error("Could not start Collective Refresh Protocol  : ", err)
			t.Fail()
		}

		for _, N := range nbnodes {
			t.Run(fmt.Sprintf("/local/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalRefresh(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory, plaintext)
			})
			t.Run(fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalRefresh(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory, plaintext)

			})

		}
	}

}

func testLocalRefresh(t *testing.T, params *bfv.Parameters, N int, local *onet.LocalTest, storageDirectory string, plaintext *bfv.Plaintext) {
	defer local.CloseAll()

	_, roster, tree := local.GenTree(N, true)

	lt, err := utils.GetLocalTestForRoster(roster, params, storageDirectory)
	//to clean up afterwards.
	defer func() {
		err = lt.TearDown(false)
		if err != nil {
			t.Fatal(err)
		}
	}()
	pi, err := local.CreateProtocol(fmt.Sprintf("CollectiveRefreshTest-%d", params.LogN), tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	rkp := pi.(*protocols.RefreshProtocol)
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

	//check if the resulting cipher text decrypted with SkOutput works
	encoder := bfv.NewEncoder(params)
	DecryptorInput := bfv.NewDecryptor(params, lt.IdealSecretKey0)
	//Expected result
	expected := encoder.DecodeUint(plaintext)
	decoded := encoder.DecodeUint(DecryptorInput.DecryptNew(&rkp.FinalCiphertext))
	if !utils.Equalslice(expected, decoded) {
		t.Fatal("Decryption failed")
	}

	log.Lvl1("Success")

}
