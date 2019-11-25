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

func TestCollectiveSwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	const nbnodes = 3
	log.SetDebugVisible(4)

	log.Lvl1("Setting up context and plaintext/ciphertext of reference")
	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		t.Fail()
	}

	CipherText := bfvCtx.NewRandomCiphertext(1)
	log.Lvl1("Set up done - Starting protocols")
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeySwitchingTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		log.Lvl1("CKS test protocol")
		proto, err := protocols.NewCollectiveKeySwitching(tni)
		if err != nil {
			return nil, err
		}

		instance := proto.(*protocols.CollectiveKeySwitchingProtocol)
		instance.Params = protocols.SwitchingParameters{
			Params:       bfv.DefaultParams[0],
			SkInputHash:  "sk0",
			SkOutputHash: "sk1",
			Ciphertext:   *CipherText,
		}
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	//can start protocol
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)
	pi, err := local.CreateProtocol("CollectiveKeySwitchingTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*protocols.CollectiveKeySwitchingProtocol)

	log.Lvl4("Starting cksp")
	err = cksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}

	log.Lvl1("Collective key switching done. Now comparing the cipher texts. ")

	<-time.After(2 * time.Second)

	//From here check that Original ciphertext decrypted under SkInput === Resulting ciphertext decrypted under SkOutput

	tmp0 := bfvCtx.ContextKeys().NewPoly()
	tmp1 := bfvCtx.ContextKeys().NewPoly()
	for _, server := range local.Overlays {

		si := server.ServerIdentity().String()
		log.Lvl1("name : ", si)

		sk0, err := utils.GetSecretKey(bfvCtx, "sk0"+si)
		if err != nil {
			log.Error("error : ", err)
		}
		sk1, err := utils.GetSecretKey(bfvCtx, "sk1"+si)
		if err != nil {
			log.Error("err : ", err)
		}

		bfvCtx.ContextKeys().Add(tmp0, sk0.Get(), tmp0)
		bfvCtx.ContextKeys().Add(tmp1, sk1.Get(), tmp1)

	}
	SkInput := new(bfv.SecretKey)
	SkOutput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	SkOutput.Set(tmp1)

	encoder := bfvCtx.NewEncoder()
	if err != nil {
		log.Error("Could not start encoder : ", err)
		t.Fail()
	}

	DecryptorInput := bfvCtx.NewDecryptor(SkInput)
	if err != nil {
		log.Error(err)
		t.Fail()
	}
	//expected
	ReferencePlaintext := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(ReferencePlaintext)

	DecryptorOutput := bfvCtx.NewDecryptor(SkOutput)
	if err != nil {
		log.Error(err)
		t.Fail()
	}
	i := 0
	for i < nbnodes {
		newCipher := (<-cksp.ChannelCiphertext).Ciphertext
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
			cksp.Done()
			return

		}
		i++
	}
	cksp.Done()
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
