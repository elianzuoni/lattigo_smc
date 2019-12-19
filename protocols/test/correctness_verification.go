package test

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
)

//CheckCorrectnessCPKG
func CheckCorrectnessCPKG(ckgp *protocols.CollectiveKeyGenerationProtocol, err error, t *testing.T) {
	keys := make([]bfv.PublicKey, len(ckgp.Roster().List))
	for i := 0; i < len(ckgp.Roster().List); i++ {
		//get the keys.

		keys[i] = (<-ckgp.ChannelPublicKey).PublicKey
	}
	for _, k1 := range keys {
		for _, k2 := range keys {
			err = utils.CompareKeys(k1, k2)
			if err != nil {
				log.Error("Error in polynomial comparison : ", err)
				t.Fail()
			}
		}
	}
}

//CheckCorrectnessCKS
func CheckCorrectnessCKS(err error, t *testing.T, local *onet.LocalTest, CipherText *bfv.Ciphertext, cksp *protocols.CollectiveKeySwitchingProtocol, params *bfv.Parameters, storageDirectory string) {
	tmp0 := params.NewPolyQ()
	tmp1 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range local.Overlays {

		sk0, err := utils.GetSecretKey(params, server.ServerIdentity().ID, storageDirectory)
		if err != nil {
			log.Error("error : ", err)
		}
		sk1, err := utils.GetSecretKey(params, server.ServerIdentity().ID, storageDirectory)
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
	for i < len(cksp.List()) {
		newCipher := (<-cksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(params)
		DecryptorOutput.Decrypt(&newCipher, res)

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

//CheckCorrectnessPCKS
func CheckCorrectnessPCKS(err error, t *testing.T, tree *onet.Tree, SkOutput *bfv.SecretKey, CipherText *bfv.Ciphertext, pcksp *protocols.CollectivePublicKeySwitchingProtocol, params *bfv.Parameters, storageDirectory string) {
	i := 0
	tmp0 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		t.Fatal(err)
	}
	for i < len(tree.Roster.List) {
		si := tree.Roster.List[i]
		sk0, err := utils.GetSecretKey(params, si.ID, storageDirectory)
		if err != nil {
			fmt.Print("error : ", err)
			t.Fatal(err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)

		i++
	}
	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	DecryptorOutput := bfv.NewDecryptor(params, SkOutput)
	DecryptorInput := bfv.NewDecryptor(params, SkInput)
	encoder := bfv.NewEncoder(params)
	//Get expected result.
	decrypted := DecryptorInput.DecryptNew(CipherText)
	expected := encoder.DecodeUint(decrypted)
	i = 0
	for i < len(tree.Roster.List) {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(params)
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl2("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			t.Fail()
			return
		}
		i++
	}
	log.Lvl1("Got all matches on ciphers.")

	return
}

//CheckCorrectnessRKG
func CheckCorrectnessRKG(i int, tree *onet.Tree, t *testing.T, ctxPQ *ring.Context, RelinProtocol *protocols.RelinearizationKeyProtocol, err error, storageDirectory string, params *bfv.Parameters) {
	log.Lvl1("Collecting the relinearization keys")
	nbnodes := len(tree.Roster.List)
	i = 0
	tmp0 := params.NewPolyQP()
	for i < nbnodes {
		si := tree.Roster.List[i]
		sk0, err := utils.GetSecretKey(params, si.ID, storageDirectory)
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

func CheckCorrectnessRefresh(err error, t *testing.T, local *onet.LocalTest, CipherText *bfv.Ciphertext, rkp *protocols.RefreshKeyProtocol, storageDirectory string, params *bfv.Parameters) {
	tmp0 := params.NewPolyQP()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range local.Overlays {

		si := server.ServerIdentity()
		log.Lvl1("name : ", si)

		sk0, err := utils.GetSecretKey(params, si.ID, storageDirectory)
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
	nbnodes := len(rkp.Roster().List)
	for i < nbnodes {
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
