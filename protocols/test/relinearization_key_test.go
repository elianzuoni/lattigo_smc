package test

import (
	"fmt"
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

func TestRelinearizationKeyLocal(t *testing.T) {
	var nbnodes = []int{3, 8, 16}
	var paramsSets = bfv.DefaultParams[:3]
	var storageDirectory = "tmp/"
	if testing.Short() {
		nbnodes = nbnodes[:1]
		paramsSets = paramsSets[:1]
	}

	log.SetDebugVisible(1)

	for _, params := range paramsSets {
		ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
		crpGenerator := ring.NewCRPGenerator(nil, ctxPQ)

		modulus := params.Moduli.Qi
		crp := make([]*ring.Poly, len(modulus))
		for j := 0; j < len(modulus); j++ {
			crp[j] = crpGenerator.ClockNew()
		}
		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("CollectiveRelinearizationTest-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, err error) {
				log.Lvl3("New Relinearization ! ")
				instance, err = protocols.NewRelinearizationKey(tni)
				if err != nil {
					return nil, err
				}

				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
				if err != nil {
					return nil, err
				}

				err = instance.(*protocols.RelinearizationKeyProtocol).Init(*params, *lt.SecretKeyShares0[tni.ServerIdentity().ID], crp)
				return
			}); err != nil {
			log.Error("Could not start Relinearization : ", err)
			t.Fatal(err)
		}

		for _, N := range nbnodes {
			t.Run(fmt.Sprintf("/local/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalRKG(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory)
			})
			t.Run(fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalRKG(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory)
			})
		}
	}
}

func testLocalRKG(t *testing.T, params *bfv.Parameters, N int, local *onet.LocalTest, storageDirectory string) {
	defer local.CloseAll()

	_, roster, tree := local.GenTree(N, true)

	lt, err := utils.GetLocalTestForRoster(roster, params, storageDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = lt.TearDown(false)
		if err != nil {
			t.Fatal(err)
		}
	}()

	//The parameters are sk,crp,bfvParams
	pi, err := local.CreateProtocol(fmt.Sprintf("CollectiveRelinearizationTest-%d", params.LogN), tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	RelinProtocol := pi.(*protocols.RelinearizationKeyProtocol)

	//Now we can start the protocol
	log.Lvl1("RLK protocol start ! ")
	now := time.Now()
	err = RelinProtocol.Start()

	if err != nil {
		log.Error("Could not start relinearization protocol : ", err)
		t.Fail()
	}
	RelinProtocol.WaitDone()
	elapsed := time.Since(now)
	log.Lvl1("**********RELINEARIZATION KEY PROTOCOL DONE ***************")
	log.Lvl1("**********Time elapsed :", elapsed, "***************")

	sk := lt.IdealSecretKey0
	pk := bfv.NewKeyGenerator(params).GenPublicKey(sk)
	encryptor_pk := bfv.NewEncryptorFromPk(params, pk)
	encoder := bfv.NewEncoder(params)

	pt := bfv.NewPlaintext(params)

	expected := params.NewPolyQP()
	encoder.EncodeUint(expected.Coeffs[0], pt)
	CipherText := encryptor_pk.EncryptNew(pt)
	//multiply it !
	evaluator := bfv.NewEvaluator(params)
	MulCiphertext := evaluator.MulNew(CipherText, CipherText)
	//we want to relinearize MulCiphertexts
	ExpectedCoeffs := params.NewPolyQP()
	ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	ctxPQ.MulCoeffs(expected, expected, ExpectedCoeffs)
	evalkey := RelinProtocol.EvaluationKey
	ResCipher := evaluator.RelinearizeNew(MulCiphertext, evalkey)

	decryptor := bfv.NewDecryptor(params, sk)
	resDecrypted := decryptor.DecryptNew(ResCipher)
	resDecoded := encoder.DecodeUint(resDecrypted)
	if !utils.Equalslice(ExpectedCoeffs.Coeffs[0], resDecoded) {
		log.Error("Decryption failed")
		t.Fatal()
	}
	log.Lvl1("Success.")

}
