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
)

func TestCollectivePublicKeySwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	const nbnodes = 10
	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)

	params := bfv.DefaultParams[0]

	SkOutput := bfv.NewKeyGenerator(params).NewSecretKey()
	publickey := bfv.NewKeyGenerator(params).NewPublicKey(SkOutput)

	CipherText := bfv.NewCiphertextRandom(params, 1)

	//Inject the parameters for each node
	if _, err := onet.GlobalProtocolRegister("CollectivePublicKeySwitchingTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		log.Lvl1("PCKS test protocol")
		proto, err := protocols.NewCollectivePublicKeySwitching(tni)
		if err != nil {
			return nil, err
		}

		instance := proto.(*protocols.CollectivePublicKeySwitchingProtocol)
		instance.Params = *bfv.DefaultParams[0]
		instance.PublicKey = *publickey
		instance.Ciphertext = *CipherText
		instance.Sk.SecretKey = "sk0"
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectivePublicKeySwitchingTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	pcksp := pi.(*protocols.CollectivePublicKeySwitchingProtocol)

	log.Lvl4("Starting cksp")

	err = pcksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	log.Lvl1("Public Collective key switching done. Now comparing the cipher texts. ")

	i := 0
	tmp0 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	for i < nbnodes {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(params, "sk0"+si)
		if err != nil {
			fmt.Print("error : ", err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)

		i++
	}

	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)

	DecryptorOutput := bfv.NewDecryptor(params, SkOutput)

	DecryptorInput := bfv.NewDecryptor(params, SkInput)

	encoder := bfv.NewEncoder(params)

	//Get expected result.
	decrypted := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(decrypted)

	i = 0
	for i < nbnodes {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(params)
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl2("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			t.Fail()
			pcksp.Done()
			return

		}
		i++
	}
	pcksp.Done()
	log.Lvl1("Got all matches on ciphers.")
	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Success")
	//TODO - make closing more "clean" as here we force to close it once the key exchange is done.
	//repeat n times

}
