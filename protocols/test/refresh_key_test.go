package test

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
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
var RPNobes = 3

func TestRefreshProtocol(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	log.SetDebugVisible(1)

	log.Lvl1("Setting up context and plaintext/ciphertext of reference")
	params := bfv.DefaultParams[0]

	CipherText := bfv.NewCiphertextRandom(params, 1)

	crp := dbfv.NewCRPGenerator(params, nil)
	crp.Seed([]byte{})
	crs := *crp.ClockNew() //crp.ClockNew() is not thread safe ?

	log.Lvl1("Set up done - Starting protocols")
	//register the test protocol
	if _, err := onet.GlobalProtocolRegister("CollectiveRefreshKeyTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		//Use a local function so we can use ciphertext !
		proto, err := protocols.NewCollectiveRefresh(tni)
		if err != nil {
			return nil, err
		}
		SkInput, err := utils.GetSecretKey(params, SkInputHash+tni.ServerIdentity().String())
		if err != nil {
			return nil, err
		}

		instance := proto.(*protocols.RefreshKeyProtocol)
		instance.Ciphertext = *CipherText
		instance.CRS = crs
		instance.Sk = *SkInput
		instance.Params = *params
		return instance, nil

	}); err != nil {
		log.Error("Could not start RefreshKeyTest : ", err)
		t.Fail()

	}

	//can start protocol
	log.Lvl1("Started to test refresh key locally with nodes amount : ", RPNobes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(RPNobes, true)
	pi, err := local.CreateProtocol("CollectiveRefreshKeyTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	rkp := pi.(*protocols.RefreshKeyProtocol)
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

	//From here check that Original ciphertext decrypted under SkInput === Resulting ciphertext decrypted under SkOutput
	if VerifyCorrectness {
		CheckCorrectnessRefresh(err, t, local, CipherText, rkp)
	}
	rkp.Done()

	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Test over.")
	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	//local.CloseAll()
	*/

}

func CheckCorrectnessRefresh(err error, t *testing.T, local *onet.LocalTest, CipherText *bfv.Ciphertext, rkp *protocols.RefreshKeyProtocol) {
	tmp0 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range local.Overlays {

		si := server.ServerIdentity().String()
		log.Lvl1("name : ", si)

		sk0, err := utils.GetSecretKey(params, SkInputHash+si)
		if err != nil {
			log.Error("error : ", err)
			t.Fatal(err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)
	}
	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	d, _ := SkInput.MarshalBinary()
	log.Lvl1("Master key : ", d[0:25])
	encoder := bfv.NewEncoder(params)
	DecryptorInput := bfv.NewDecryptor(params, SkInput)
	//expected
	ReferencePlaintext := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(ReferencePlaintext)
	log.Lvl1("test is downloading the ciphertext..expected pt: ", expected[0:25])
	i := 0
	for i < RPNobes {
		newCipher := (<-rkp.ChannelCiphertext).Ciphertext
		res := DecryptorInput.DecryptNew(&newCipher)

		decoded := encoder.DecodeUint(res)

		log.Lvl1("Comparing a pt.. have : ", decoded[0:25])
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			t.Fail()
			return

		}
		i++
	}

	if !t.Failed() {
		log.Lvl1("Got all matches on ciphers.")

	}
}
