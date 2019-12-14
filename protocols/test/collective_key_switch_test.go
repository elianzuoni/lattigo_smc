package test

import (
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

//Global variables to modify tests.
var CKSNbnodes = 5
var SkInputHash = "sk1"

var SkOutputHash = "sk1"
var VerifyCorrectness = false

func TestCollectiveSwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)

	log.Lvl1("Setting up context and plaintext/ciphertext of reference")
	params := (bfv.DefaultParams[0])

	CipherText := bfv.NewCiphertextRandom(params, 1)
	log.Lvl1("Set up done - Starting protocols")
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveKeySwitchingTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		proto, err := protocols.NewCollectiveKeySwitching(tni)
		if err != nil {
			return nil, err
		}
<<<<<<< Updated upstream
		SkInput, err := utils.GetSecretKey(params, SkInputHash+tni.ServerIdentity().String())
		if err != nil {
			return nil, err
		}
		SkOutput, err := utils.GetSecretKey(params, SkOutputHash+tni.ServerIdentity().String())
		if err != nil {
			return nil, err
		}
		instance := proto.(*protocols.CollectiveKeySwitchingProtocol)
		instance.Params = protocols.SwitchingParameters{
			Params:     *params,
			SkInput:    *SkInput, //todo create real key here
			SkOutput:   *SkOutput,
			Ciphertext: *CipherText,
=======


		instance := proto.(*protocols.CollectiveKeySwitchingProtocol)
		instance.Params = protocols.SwitchingParameters{
			Params:       *bfv.DefaultParams[0],
			SkInputHash:  "sk0",//todo create real key here
			SkOutputHash: "sk1",
			Ciphertext:   *CipherText,
>>>>>>> Stashed changes
		}
		return instance, nil

	}); err != nil {
		log.Error("Could not start CollectiveKeySwitchingTest : ", err)
		t.Fail()

	}

	//can start protocol
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", CKSNbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(CKSNbnodes, true)
	pi, err := local.CreateProtocol("CollectiveKeySwitchingTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*protocols.CollectiveKeySwitchingProtocol)
	now := time.Now()
	log.Lvl4("Starting cksp")
	err = cksp.Start()
	if err != nil {
		t.Fatal("Could not start the tree : ", err)
	}
	cksp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("*****************Collective key switching done.******************")
	log.Lvl1("*****************Time elapsed : ", elapsed, "*******************")

	//From here check that Original ciphertext decrypted under SkInput === Resulting ciphertext decrypted under SkOutput
	if VerifyCorrectness {
		CheckCorrectness(err, t, local, CipherText, cksp)
	}

	cksp.Done()
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

func CheckCorrectness(err error, t *testing.T, local *onet.LocalTest, CipherText *bfv.Ciphertext, cksp *protocols.CollectiveKeySwitchingProtocol) {
	tmp0 := params.NewPolyQ()
	tmp1 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range local.Overlays {

		si := server.ServerIdentity().String()
		log.Lvl3("name : ", si)

		sk0, err := utils.GetSecretKey(params, "sk0"+si)
		if err != nil {
			log.Error("error : ", err)
		}
		sk1, err := utils.GetSecretKey(params, "sk1"+si)
		if err != nil {
			log.Error("err : ", err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)
		ctx.Add(tmp1, sk1.Get(), tmp1)
	}
	SkInput := new(bfv.SecretKey)
	SkOutput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	SkOutput.Set(tmp1)
	encoder := bfv.NewEncoder(params)
	DecryptorInput := bfv.NewDecryptor(params, SkInput)
	//expected
	ReferencePlaintext := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(ReferencePlaintext)
	DecryptorOutput := bfv.NewDecryptor(params, SkOutput)
	log.Lvl1("test is downloading the ciphertext..")
	i := 0
	for i < CKSNbnodes {
		newCipher := (<-cksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(params)
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl1("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			t.Fail()
			cksp.Done()

		}
		i++
	}
	log.Lvl1("Got all matches on ciphers.")
}
