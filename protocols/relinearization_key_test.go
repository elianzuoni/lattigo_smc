package protocols

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"testing"
	"time"
)

func TestNewRelinearizationKey(t *testing.T) {
	//first generate a secret key and from shards and the resulting public key
	nbnodes := 3
	log.SetDebugVisible(1)
	log.Lvl1("Started to test relinearization protocol with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)
	SKHash := "sk0"
	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		t.Fail()
	}
	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	for i < nbnodes {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(bfvCtx, SKHash+si)
		if err != nil {
			fmt.Print("error : ", err)
		}

		bfvCtx.ContextQ().Add(tmp0, sk0.Get(), tmp0)

		i++
	}

	Sk := new(bfv.SecretKey)
	Sk.Set(tmp0)
	Pk := bfvCtx.NewKeyGenerator().NewPublicKey(Sk)
	encryptor_pk,_ := bfvCtx.NewEncryptorFromPk(Pk)
	//encrypt some cipher text...

	PlainText := bfvCtx.NewPlaintext()
	encoder, err := bfvCtx.NewBatchEncoder()
	expected := bfvCtx.ContextT().NewUniformPoly()

	err = encoder.EncodeUint(expected.Coeffs[0], PlainText)
	if err != nil {
		log.Print("Could not encode plaintext : ", err)
		t.Fail()
	}



	CipherText, err := encryptor_pk.EncryptNew(PlainText)

	if err != nil {
		log.Print("error in encryption : ", err)
		t.Fail()
	}
	//multiply it !
	evaluator := bfvCtx.NewEvaluator()

	MulCiphertext ,_ := evaluator.MulNew(CipherText,CipherText)
	//we want to relinearize MulCiphertexts
	ExpectedCoeffs := bfvCtx.ContextT().NewPoly()
	bfvCtx.ContextT().MulCoeffs(expected, expected, ExpectedCoeffs)
	//in the end of relin we should have RelinCipher === ExpectedCoeffs.
	contextQ := bfvCtx.ContextQ()
	bitLog := uint64((60 + (60 % bitDecomp)) / bitDecomp)

	//Parameters ***************************
	//Computation for the crp (a)
	crpGenerators := make([]*dbfv.CRPGenerator, nbnodes)
	for i := 0; i < nbnodes; i++ {
		crpGenerators[i], err = dbfv.NewCRPGenerator(nil, contextQ)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		crpGenerators[i].Seed([]byte{})
	}
	crp := make([][]*ring.Poly, len(contextQ.Modulus))
	for j := 0; j < len(contextQ.Modulus); j++ {
		crp[j] = make([]*ring.Poly, bitLog)
		for u := uint64(0); u < bitLog; u++ {
			crp[j][u] = crpGenerators[0].Clock()
		}
	}


	//The parameters are sk,crp,bfvParams
	pi, err := local.CreateProtocol("RelinearizationKeyProtocol", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}


	RelinProtocol := pi.(*RelinearizationKeyProtocol)
	RelinProtocol.Params = bfv.DefaultParams[0]
	RelinProtocol.Sk = SK{"sk0"}
	RelinProtocol.crp = CRP{a:crp}
	<- time.After(2*time.Second)

	//Now we can start the protocol
	err = RelinProtocol.Start()
	defer RelinProtocol.Done()
	if err != nil{
		log.Error("Could not start relinearization protocol : " , err )
		t.Fail()
	}

	<- time.After(3*time.Second)
	log.Lvl1("Collecting the relinearization keys")
	array := make([]bfv.EvaluationKey, nbnodes)
	//check if the keys are the same for all parties
	for i := 0 ; i < nbnodes; i++{
		relkey := (<-RelinProtocol.ChannelEvalKey).EvaluationKey
		log.Lvl3("Got one evel key...")
		array[i] = relkey
	}

	err = CompareEvalKeys(array)
	if err != nil{
		log.Error("Different relinearization keys")
		t.Fail()
	}

	rlk := array[0]
	ResCipher , err := evaluator.RelinearizeNew(MulCiphertext,&rlk)
	if err != nil{
		log.Error("Could not relinearize the cipher text : ", err)
		t.Fail()
	}

	//decrypt the cipher
	decryptor,_ := bfvCtx.NewDecryptor(Sk)
	if ! utils.Equalslice(expected.Coeffs[0],encoder.DecodeUint(decryptor.DecryptNew(ResCipher))){
		log.Error("Decrypted relinearized cipher is not equal to expected plaintext")
		t.Fail()
	}

}

func CompareEvalKeys(keys []bfv.EvaluationKey) error {
	for _,k1 := range keys{
		for _ , s1 := range k1.Get(){
			for _, k2 := range keys{
				for _, s2 := range k2.Get(){
					err := CompareArray(s1.Get(),s2.Get())
					if err != nil{
						return err
					}
				}

			}
		}

	}

	return nil
}

func CompareArray(key [][][2]*ring.Poly, key2 [][][2]*ring.Poly) error  {
	if len(key) != len(key2) || len(key[0]) != len(key2[0]){
		return errors.New("Non matching length of switching keys")
	}
	for i , _ := range key{
		for j , _ := range key[i]{
			err := utils.ComparePolys(*key[i][j][0],*key2[i][j][0])
			if err != nil{
				return errors.New("Switching key do not match on index : "+string(i)+string(j)+"0")
			}
			err = utils.ComparePolys(*key[i][j][1],*key2[i][j][1])
			if err != nil{
				return errors.New("Switching key do not match on index : "+string(i)+string(j)+"1")
			}

		}
	}
	return nil

}
