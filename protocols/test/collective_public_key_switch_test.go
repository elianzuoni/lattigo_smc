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
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	const nbnodes = 10
	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)

	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		t.Fail()
	}

	SkOutput := bfvCtx.NewKeyGenerator().NewSecretKey()
	publickey := bfvCtx.NewKeyGenerator().NewPublicKey(SkOutput)

	CipherText := bfvCtx.NewRandomCiphertext(1)

	//Inject the parameters for each node
	if _, err := onet.GlobalProtocolRegister("CollectivePublicKeySwitchingTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		log.Lvl1("PCKS test protocol")
		proto, err := protocols.NewCollectivePublicKeySwitching(tni)
		if err != nil {
			return nil, err
		}

		instance := proto.(*protocols.CollectivePublicKeySwitchingProtocol)
		instance.Params = bfv.DefaultParams[0]
		instance.PublicKey = *publickey
		instance.Ciphertext = *CipherText
		instance.Sk.SecretKey = "sk0"
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	local := onet.NewLocalTest(utils.SUITE)
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

	<-time.After(2 * time.Second)

	log.Lvl1("Public Collective key switching done. Now comparing the cipher texts. ")

	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	for i < nbnodes {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(bfvCtx, "sk0"+si)
		if err != nil {
			fmt.Print("error : ", err)
		}

		bfvCtx.ContextQ().Add(tmp0, sk0.Get(), tmp0)

		i++
	}

	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)

	DecryptorOutput := bfvCtx.NewDecryptor(SkOutput)
	if err != nil {
		log.Error("Error on decryptor : ", err)
		t.Fail()
	}

	DecryptorInput := bfvCtx.NewDecryptor(SkInput)
	if err != nil {
		log.Error("Error on decryptor : ", err)
		t.Fail()
	}

	encoder := bfvCtx.NewEncoder()
	if err != nil {
		log.Error("Could not start batch encoder : ", err)
		t.Fail()
	}

	//Get expected result.
	decrypted := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(decrypted)

	i = 0
	for i < nbnodes {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfvCtx.NewPlaintext()
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl1("Comparing a cipher..")
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

//func NewPublicCollectiveKeySwitchingTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
//	log.Lvl1("PING")
//	proto, err := protocols.NewCollectivePublicKeySwitching(tni)
//	if err != nil{
//		return nil, err
//	}
//	instance := proto.(*protocols.CollectiveKeyGenerationProtocol)
//	instance.Params = bfv.DefaultParams[0]
//	return instance, nil
//}

/*

 */
