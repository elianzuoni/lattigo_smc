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

var PublicKeySwitchNbNodes = 5
var SkHash = "sk0"
var CPKSparams = bfv.DefaultParams[0]

func TestCollectivePublicKeySwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", PublicKeySwitchNbNodes)

	SkOutput := bfv.NewKeyGenerator(CPKSparams).NewSecretKey()
	publickey := bfv.NewKeyGenerator(CPKSparams).NewPublicKey(SkOutput)

	CipherText := bfv.NewCiphertextRandom(CPKSparams, 1)

	//Inject the parameters for each node
	if _, err := onet.GlobalProtocolRegister("CollectivePublicKeySwitchingTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		log.Lvl4("PCKS test protocol")
		proto, err := protocols.NewCollectivePublicKeySwitching(tni)
		if err != nil {
			return nil, err
		}
		sk, err := utils.GetSecretKey(CPKSparams, SkHash+tni.ServerIdentity().String())
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

	_, _, tree := local.GenTree(PublicKeySwitchNbNodes, true)

	pi, err := local.CreateProtocol("CollectivePublicKeySwitchingTest", tree)
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
		VerifyMatches(err, t, tree, SkOutput, CipherText, pcksp)
	}

	pcksp.Done()

	log.Lvl1("Success")

}

func VerifyMatches(err error, t *testing.T, tree *onet.Tree, SkOutput *bfv.SecretKey, CipherText *bfv.Ciphertext, pcksp *protocols.CollectivePublicKeySwitchingProtocol) {
	i := 0
	tmp0 := CPKSparams.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<CPKSparams.LogN, CPKSparams.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	for i < PublicKeySwitchNbNodes {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(CPKSparams, SkHash+si)
		if err != nil {
			fmt.Print("error : ", err)
			t.Fatal(err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)

		i++
	}
	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	DecryptorOutput := bfv.NewDecryptor(CPKSparams, SkOutput)
	DecryptorInput := bfv.NewDecryptor(CPKSparams, SkInput)
	encoder := bfv.NewEncoder(CPKSparams)
	//Get expected result.
	decrypted := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(decrypted)
	i = 0
	for i < PublicKeySwitchNbNodes {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(CPKSparams)
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl2("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			t.Fail()
			return
		}
		i++
	}
	log.Lvl1("Got all matches on ciphers.")

	return
}
