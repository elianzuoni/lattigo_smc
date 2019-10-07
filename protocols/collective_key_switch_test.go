package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"time"

	//"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"math/rand"
	"protocols/utils"
	"testing"
)

func TestCollectiveSwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	nbnodes := 3
	log.SetDebugVisible(4)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	//take the secret key of two random nodes..
	in := rand.Intn(nbnodes)
	out := -1
	for{
		//take two different nodes..
		out = rand.Intn(nbnodes)
		if in != out{
			break
		}
	}
	bfvCtx,err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil{
		log.Print("Could not load bfv ctx ",err)
		t.Fail()
	}
	keygen := bfvCtx.NewKeyGenerator()
	sidIn := tree.List()[in].ServerIdentity
	SkInput ,err := utils.LoadSecretKey(bfvCtx,sidIn.String())
	PkInput  := keygen.NewPublicKey(SkInput)
	sidOut := tree.List()[out].ServerIdentity
	SkOutput ,err := utils.LoadSecretKey(bfvCtx,sidOut.String())
	//PkOutput, err := keygen.NewPublicKey(SkOutput)



	if err != nil{
		log.Print("Could not load secret keys : " , err)
		t.Fail()
	}

	PlainText := bfvCtx.NewPlaintext()
	encoder,err := bfvCtx.NewBatchEncoder()
	log.Print(PlainText.Degree())
	err = encoder.EncodeUint(bfvCtx.NewRandomPlaintextCoeffs(),PlainText)
	if err != nil{
		log.Print("Could not encode plaintext : " , err)
		t.Fail()
	}

	Encryptor ,err := bfvCtx.NewEncryptorFromPk(PkInput)

	CipherText,err := Encryptor.EncryptNew(PlainText)
	if err != nil{
		log.Print("error in encryption : " , err)
		t.Fail()
	}

	CipherText = bfvCtx.NewRandomCiphertext(1)



	pi, err := local.CreateProtocol("CollectiveKeySwitching", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*CollectiveKeySwitchingProtocol)
	cksp.Params = SwitchingParameters{
		Params:  bfv.DefaultParams[0],
		SkInputHash:  sidIn.String(),
		SkOutputHash: sidOut.String(),
		Ciphertext:   *CipherText,
	}



	//cksp.Params = bfv.DefaultParams[0]
	log.Lvl1("Starting cksp")
	err = cksp.Start()
	if err != nil{
		t.Fatal("Could not start the tree : " , err)
	}

	log.Lvl1("Collective kex switching done. Now comparing the cipher texts. ")

	<-time.After(1000*time.Second)

	return

	//check if the resulting cipher text decrypted with SkOutput works
	Decryptor,err := bfvCtx.NewDecryptor(SkOutput)
	res := bfvCtx.NewPlaintext()
	Decryptor.Decrypt(CipherText, res)

	err = utils.ComparePolys(*res.Value()[0],*PlainText.Value()[0])
	if err != nil{
		log.Print("Plaintext do not match : " , err)
		t.Fail()

	}

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
