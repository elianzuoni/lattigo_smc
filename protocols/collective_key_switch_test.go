package protocols

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"time"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
	"testing"
)

func TestCollectiveSwitching(t *testing.T) {
	//to do this we need to have some keys already.
	//for this we can set up with the collective key generation
	const nbnodes = 3
	//log.SetDebugVisible(4)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)


	bfvCtx,err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil{
		log.Print("Could not load bfv ctx ",err)
		t.Fail()
	}
	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	tmp1 := bfvCtx.ContextQ().NewPoly()
	for i < nbnodes{
		si := tree.Roster.List[i].String()
		sk0 ,err := utils.GetSecretKey(bfvCtx,"sk0"+si)
		if err!=nil{
			fmt.Print("error : " , err)
		}
		sk1 , err := utils.GetSecretKey(bfvCtx,"sk1"+si)
		if err != nil{
			fmt.Print("err : " , err )
		}

		bfvCtx.ContextQ().Add(tmp0,sk0.Get(),tmp0)
		bfvCtx.ContextQ().Add(tmp1,sk1.Get(),tmp1)




		i++
	}
	SkInput := new(bfv.SecretKey)
	SkOutput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	SkOutput.Set(tmp1)


	keygen := bfvCtx.NewKeyGenerator()
	PkInput  := keygen.NewPublicKey(SkInput)


	ski,_ := SkInput.MarshalBinary()
	log.Lvl4("At start ski  : " , ski[0:25])
	sko,_ := SkOutput.MarshalBinary()
	log.Lvl4("At start  sko  : " , sko[0:25])


	if err != nil{
		log.Print("Could not load secret keys : " , err)
		t.Fail()
	}

	PlainText := bfvCtx.NewPlaintext()
	encoder,err := bfvCtx.NewBatchEncoder()
	log.Print(PlainText.Degree())
	expected := bfvCtx.NewRandomPlaintextCoeffs()

	err = encoder.EncodeUint(expected,PlainText)
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



	pi, err := local.CreateProtocol("CollectiveKeySwitching", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*CollectiveKeySwitchingProtocol)
	cksp.Params = SwitchingParameters{
		Params:  bfv.DefaultParams[0],
		SkInputHash:  "sk0",
		SkOutputHash: "sk1",
		Ciphertext:   *CipherText,
	}



	//cksp.Params = bfv.DefaultParams[0]
	log.Lvl4("Starting cksp")
	err = cksp.Start()
	if err != nil{
		t.Fatal("Could not start the tree : " , err)
	}

	log.Lvl1("Collective key switching done. Now comparing the cipher texts. ")

	<-time.After(2*time.Second)


	Decryptor,err := bfvCtx.NewDecryptor(SkOutput)

	i = 0
	for i < nbnodes{
		newCipher := (<- cksp.ChannelCiphertext).Ciphertext
		d,_ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : " , d[0:25])
		res := bfvCtx.NewPlaintext()
		Decryptor.Decrypt(&newCipher , res)


		log.Lvl1("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded,expected)

		if !ok{
			log.Print("Plaintext do not match ")
			t.Fail()
			cksp.Done()
			return

		}
		i ++
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
