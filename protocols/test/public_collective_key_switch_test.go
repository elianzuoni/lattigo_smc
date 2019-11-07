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

func TestPublicCollectiveSwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	const nbnodes = 10
	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		t.Fail()
	}
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
	SkOutput := bfvCtx.NewKeyGenerator().NewSecretKey()
	publickey := bfvCtx.NewKeyGenerator().NewPublicKey(SkOutput)

	ski, _ := SkInput.MarshalBinary()
	log.Lvl4("At start ski  : ", ski[0:25])

	if err != nil {
		log.Print("Could not load secret keys : ", err)
		t.Fail()
	}

	PlainText := bfvCtx.NewPlaintext()
	encoder, err := bfvCtx.NewBatchEncoder()
	expected := bfvCtx.NewRandomPlaintextCoeffs()

	err = encoder.EncodeUint(expected, PlainText)
	if err != nil {
		log.Print("Could not encode plaintext : ", err)
		t.Fail()
	}

	Encryptor, err := bfvCtx.NewEncryptorFromSk(SkInput)

	CipherText, err := Encryptor.EncryptNew(PlainText)

	if err != nil {
		log.Print("error in encryption : ", err)
		t.Fail()
	}

	pi, err := local.CreateProtocol("PublicCollectiveKeySwitching", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	pcksp := pi.(*protocols.PublicCollectiveKeySwitchingProtocol)
	pcksp.Params = bfv.DefaultParams[0]
	pcksp.Sk = protocols.SK{"sk0"}
	pcksp.PublicKey = *publickey
	pcksp.Ciphertext = *CipherText

	//cksp.Params = bfv.DefaultParams[0]
	log.Lvl4("Starting cksp")

	err = pcksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	<-time.After(2 * time.Second)

	log.Lvl1("Public Collective key switching done. Now comparing the cipher texts. ")

	Decryptor, err := bfvCtx.NewDecryptor(SkOutput)
	i = 0
	for i < nbnodes {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfvCtx.NewPlaintext()
		Decryptor.Decrypt(&newCipher, res)

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
	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	//local.CloseAll()
	*/
	//then choose two random sk from two participant

	//chose a random cipher text.

	//go from skIn -> skOut -> skIn and check equality of cipher text.

	//repeat n times

}
