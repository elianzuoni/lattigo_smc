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

const SKHash = "sk0"

func TestNewRelinearizationKey(t *testing.T) {
	//first generate a secret key and from shards and the resulting public key
	log.SetDebugVisible(3)
	log.Lvl1("Started to test relinearization protocol with nodes amount : ", nbnodes)

	params := bfv.DefaultParams[0]

	ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	crpGenerator := ring.NewCRPGenerator(nil, ctxPQ)
	modulus := params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGenerator.ClockNew()
	}

	log.Lvl1("Setup ok - Starting protocols")
	if _, err := onet.GlobalProtocolRegister("RelinearizationKeyTest", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		protocol, err := protocols.NewRelinearizationKey(tni)
		if err != nil {
			return nil, err
		}
		sk, err := utils.GetSecretKey(params, SKHash+tni.ServerIdentity().String())
		if err != nil {
			return nil, err
		}
		instance := protocol.(*protocols.RelinearizationKeyProtocol)
		instance.Params = *params
		instance.Sk = *sk
		instance.Crp.A = crp
		return instance, nil
	}); err != nil {
		log.Error("Could not start Relin key protocol : ", err)
		t.Fail()
	}

	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)

	//The parameters are sk,crp,bfvParams
	pi, err := local.CreateProtocol("RelinearizationKeyTest", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	RelinProtocol := pi.(*protocols.RelinearizationKeyProtocol)

	//Now we can start the protocol
	now := time.Now()
	err = RelinProtocol.Start()
	if err != nil {
		log.Error("Could not start relinearization protocol : ", err)
		t.Fail()
	}

	RelinProtocol.Wait()
	elapsed := time.Since(now)
	log.Lvl1("**********RELINEARIZATION KEY PROTOCOL DONE ***************")
	log.Lvl1("**********Time elapsed :", elapsed, "***************")

	if VerifyCorrectness {
		VerifyRKG(nbnodes, tree, t, ctxPQ, RelinProtocol, err)
	}
	RelinProtocol.Done()

}

func VerifyRKG(i int, tree *onet.Tree, t *testing.T, ctxPQ *ring.Context, RelinProtocol *protocols.RelinearizationKeyProtocol, err error) {
	log.Lvl1("Collecting the relinearization keys")
	i = 0
	tmp0 := params.NewPolyQP()
	for i < nbnodes {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(params, SKHash+si)
		if err != nil {
			log.Error("error : ", err)
			t.Fail()
			return
		}

		ctxPQ.Add(tmp0, sk0.Get(), tmp0)

		i++
	}
	Sk := new(bfv.SecretKey)
	Sk.Set(tmp0)
	Pk := bfv.NewKeyGenerator(params).NewPublicKey(Sk)
	encryptor_pk := bfv.NewEncryptorFromPk(params, Pk)
	//encrypt some cipher text...
	PlainText := bfv.NewPlaintext(params)
	encoder := bfv.NewEncoder(params)
	expected := params.NewPolyQP()
	encoder.EncodeUint(expected.Coeffs[0], PlainText)
	CipherText := encryptor_pk.EncryptNew(PlainText)
	//multiply it !
	evaluator := bfv.NewEvaluator(params)
	MulCiphertext := evaluator.MulNew(CipherText, CipherText)
	//we want to relinearize MulCiphertexts
	ExpectedCoeffs := params.NewPolyQP()
	ctxPQ.MulCoeffs(expected, expected, ExpectedCoeffs)
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
	ResCipher := evaluator.RelinearizeNew(MulCiphertext, &rlk)
	//decrypt the cipher
	decryptor := bfv.NewDecryptor(params, Sk)
	resDecrypted := decryptor.DecryptNew(ResCipher)
	resDecoded := encoder.DecodeUint(resDecrypted)
	if !utils.Equalslice(ExpectedCoeffs.Coeffs[0], resDecoded) {
		log.Error("Decrypted relinearized cipher is not equal to expected plaintext")
		t.Fail()
	}
	log.Lvl1("Relinearization OK")
}
