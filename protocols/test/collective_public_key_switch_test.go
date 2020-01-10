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

func TestCollectivePublicKeySwitching(t *testing.T) {
	var nbnodes = []int{3, 8, 16}
	var paramsSets = bfv.DefaultParams
	var storageDirectory = "tmp/"
	if testing.Short() {
		nbnodes = nbnodes[:1]
		paramsSets = paramsSets[:1]
	}

	log.SetDebugVisible(1)

	for _, params := range paramsSets {
		pt := bfv.NewPlaintext(params)
		var ciphertext bfv.Ciphertext
		var publicKey bfv.PublicKey
		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("CollectivePublicKeySwitchingTest-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, err error) {
				log.Lvl3("New Collective Public key switching instance for : ", tni.ServerIdentity())
				instance, err = protocols.NewCollectivePublicKeySwitching(tni)
				if err != nil {
					return nil, err
				}
				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
				if err != nil {
					return nil, err
				}
				if tni.IsRoot() {
					//init the plaintext ciphertext...
					publicKey = *bfv.NewKeyGenerator(params).GenPublicKey(lt.IdealSecretKey1)
					enc := bfv.NewEncryptorFromSk(params, lt.IdealSecretKey0)
					ciphertext = *enc.EncryptNew(pt)
				}
				err = instance.(*protocols.CollectivePublicKeySwitchingProtocol).Init(*params, publicKey, *lt.SecretKeyShares0[tni.ServerIdentity().ID], &ciphertext)

				return

			}); err != nil {
			log.Error("Could not start Collective Public key switching : ", err)
			t.Fail()
		}

		for _, N := range nbnodes {
			t.Run(fmt.Sprintf("/local/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalPCKS(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory, pt)
			})
			t.Run(fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalPCKS(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory, pt)
			})

		}

	}
}

func testLocalPCKS(t *testing.T, params *bfv.Parameters, N int, local *onet.LocalTest, storageDirectory string, plaintext *bfv.Plaintext) {
	log.Lvl1("Started to test collective public key switching with nodes amounts : ", N)
	defer local.CloseAll()

	_, roster, tree := local.GenTree(N, true)

	lt, err := utils.GetLocalTestForRoster(roster, params, storageDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = lt.TearDown(false)
		if err != nil {
			t.Fatal(err)
		}
	}()

	pi, err := local.CreateProtocol(fmt.Sprintf("CollectivePublicKeySwitchingTest-%d", params.LogN), tree)
	if err != nil {
		t.Fatal("Could not start new node : ", err)

	}
	pcks := pi.(*protocols.CollectivePublicKeySwitchingProtocol)
	log.Lvl1("Start PCKS")
	now := time.Now()
	err = pcks.Start()
	if err != nil {
		t.Fatal(err)
	}
	pcks.Wait()
	elapsed := time.Since(now)
	log.Lvl1("*************Public Collective key switching done. ************")
	log.Lvl1("*********** Time elaspsed ", elapsed, "***************")

	//now check if correct...
	encoder := bfv.NewEncoder(params)
	DecryptorOutput := bfv.NewDecryptor(params, lt.IdealSecretKey1)

	expected := encoder.DecodeUint(plaintext)
	decoded := encoder.DecodeUint(DecryptorOutput.DecryptNew(&pcks.CiphertextOut))
	if !utils.Equalslice(expected, decoded) {
		t.Fatal("Decryption failed")
	}

	log.Lvl1("Success")
}
