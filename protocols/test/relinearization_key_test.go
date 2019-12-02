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

const BitDecomp = 64

func TestNewRelinearizationKey(t *testing.T) {
	//first generate a secret key and from shards and the resulting public key
	nbnodes := 3
	log.SetDebugVisible(3)
	log.Lvl1("Started to test relinearization protocol with nodes amount : ", nbnodes)
	SKHash := "sk0"

	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Error(err)
		t.Fail()
	}

	contextQ := bfvCtx.ContextQ()
	crpGenerators := make([]*ring.CRPGenerator, nbnodes)
	for i := 0; i < nbnodes; i++ {
		crpGenerators[i] = ring.NewCRPGenerator(nil, bfvCtx.ContextKeys())
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		crpGenerators[i].Seed([]byte{})
	}
	crp := make([]*ring.Poly, len(contextQ.Modulus))
	for j := 0; j < len(contextQ.Modulus); j++ {
		crp[j] = crpGenerators[0].Clock()

	}
	log.Lvl1("Setup ok - Starting protocols")
	if _, err = onet.GlobalProtocolRegister("RelinearizationKeyTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		protocol, err := protocols.NewRelinearizationKey(tni)
		if err != nil {
			return nil, err
		}
		instance := protocol.(*protocols.RelinearizationKeyProtocol)
		instance.Params = bfv.DefaultParams[0]
		instance.Sk.SecretKey = SKHash
		instance.Crp.A = crp
		return instance, nil
	}); err != nil {
		log.Error("Could not start Relin key protocol : ", err)
		t.Fail()
	}

	local := onet.NewLocalTest(utils.SUITE)
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)

	//The parameters are sk,crp,bfvParams
	pi, err := local.CreateProtocol("RelinearizationKeyTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	RelinProtocol := pi.(*protocols.RelinearizationKeyProtocol)

	//Now we can start the protocol
	err = RelinProtocol.Start()
	defer RelinProtocol.Done()
	if err != nil {
		log.Error("Could not start relinearization protocol : ", err)
		t.Fail()
	}

	<-time.After(3 * time.Second)
	log.Lvl1("Collecting the relinearization keys")

	i := 0
	tmp0 := bfvCtx.ContextKeys().NewPoly()
	for i < nbnodes {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(bfvCtx, SKHash+si)
		if err != nil {
			log.Error("error : ", err)
			t.Fail()
			return
		}

		bfvCtx.ContextKeys().Add(tmp0, sk0.Get(), tmp0)

		i++
	}

	Sk := new(bfv.SecretKey)
	Sk.Set(tmp0)
	Pk := bfvCtx.NewKeyGenerator().NewPublicKey(Sk)
	encryptor_pk := bfvCtx.NewEncryptorFromPk(Pk)
	//encrypt some cipher text...

	PlainText := bfvCtx.NewPlaintext()
	encoder := bfvCtx.NewEncoder()
	if err != nil {
		log.Error("Error could not start encoder : ", err)
		t.Fail()
	}
	expected := bfvCtx.ContextT().NewUniformPoly()

	encoder.EncodeUint(expected.Coeffs[0], PlainText)
	if err != nil {
		log.Print("Could not encode plaintext : ", err)
		t.Fail()
	}

	CipherText := encryptor_pk.EncryptNew(PlainText)

	if err != nil {
		log.Print("error in encryption : ", err)
		t.Fail()
	}
	//multiply it !
	evaluator := bfvCtx.NewEvaluator()

	MulCiphertext := evaluator.MulNew(CipherText, CipherText)
	//we want to relinearize MulCiphertexts
	ExpectedCoeffs := bfvCtx.ContextT().NewPoly()
	bfvCtx.ContextT().MulCoeffs(expected, expected, ExpectedCoeffs)
	//in the end of relin we should have RelinCipher === ExpectedCoeffs.

	//Parameters ***************************
	//Computation for the crp (a)

	array := make([]bfv.EvaluationKey, nbnodes)
	//check if the keys are the same for all parties
	for i := 0; i < nbnodes; i++ {
		relkey := (<-RelinProtocol.ChannelEvalKey).EvaluationKey
		data, _ := relkey.MarshalBinary()
		log.Lvl3("Key starting with : ", data[0:25])
		log.Lvl3("Got one eval key...")
		array[i] = relkey
	}

	err = utils.CompareEvalKeys(array)
	if err != nil {
		log.Error("Different relinearization keys : ", err)
		t.Fail()
		return
	}
	log.Lvl1("Check : all peers have the same key ")
	rlk := array[0]
	ResCipher, err := evaluator.RelinearizeNew(MulCiphertext, &rlk)
	if err != nil {
		log.Error("Could not relinearize the cipher text : ", err)
		t.Fail()
	}

	//decrypt the cipher
	decryptor := bfvCtx.NewDecryptor(Sk)
	resDecrypted := decryptor.DecryptNew(ResCipher)
	resDecoded := encoder.DecodeUint(resDecrypted)
	if !utils.Equalslice(ExpectedCoeffs.Coeffs[0], resDecoded) {
		log.Error("Decrypted relinearized cipher is not equal to expected plaintext")
		t.Fail()
	}
	log.Lvl1("Relinearization OK")

}
