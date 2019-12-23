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

func TestRotationKeyLocal(t *testing.T) {
	var nbnodes = []int{3, 8, 16}
	var paramsSets = bfv.DefaultParams
	var storageDirectory = "tmp/"
	if testing.Short() {
		nbnodes = nbnodes[:1]
		paramsSets = paramsSets[:1]
	}

	log.SetDebugVisible(3)
	for _, params := range paramsSets {
		//prepare the crp
		ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
		crpGenerator := ring.NewCRPGenerator(nil, ctxPQ)
		modulus := params.Moduli.Qi
		crp := make([]*ring.Poly, len(modulus))
		k := uint64(1)

		for j := 0; j < len(modulus); j++ {
			crp[j] = crpGenerator.ClockNew()
		}

		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("RotationKeyTestRow-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
				rottype := bfv.RotationRow

				log.Lvl3("New rotation row ")
				instance, err := protocols.NewRotationKey(tni)
				if err != nil {
					return nil, err
				}
				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
				if err != nil {
					return nil, err
				}

				err = instance.(*protocols.RotationKeyProtocol).Init(params, *lt.SecretKeyShares0[tni.ServerIdentity().ID], bfv.Rotation(rottype), k, crp)
				return instance, err
			}); err != nil {
			t.Fatal(err)
		}

		//register protocol for colLEft
		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("RotationKeyTestLeft-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
				log.Lvl3("New rotation left ")
				rottype := bfv.RotationLeft

				instance, err := protocols.NewRotationKey(tni)
				if err != nil {
					return nil, err
				}
				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
				if err != nil {
					return nil, err
				}

				err = instance.(*protocols.RotationKeyProtocol).Init(params, *lt.SecretKeyShares0[tni.ServerIdentity().ID], bfv.Rotation(rottype), k, crp)
				return instance, err
			}); err != nil {
			t.Fatal(err)
		}
		if _, err := onet.GlobalProtocolRegister(fmt.Sprintf("RotationKeyTestRight-%d", params.LogN),
			func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
				log.Lvl3("New rotation")
				rottype := bfv.RotationRight

				instance, err := protocols.NewRotationKey(tni)
				if err != nil {
					return nil, err
				}
				lt, err := utils.GetLocalTestForRoster(tni.Roster(), params, storageDirectory)
				if err != nil {
					return nil, err
				}

				err = instance.(*protocols.RotationKeyProtocol).Init(params, *lt.SecretKeyShares0[tni.ServerIdentity().ID], bfv.Rotation(rottype), k, crp)
				return instance, err
			}); err != nil {
			t.Fatal(err)
		}

		for _, N := range nbnodes {
			//t.Run(fmt.Sprintf("/local/row/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
			//	testLocalRotKG(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory, bfv.RotationRow,k)
			//})
			//t.Run(fmt.Sprintf("/local/left/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
			//	testLocalRotKG(t, params, N, onet.NewLocalTest(suites.MustFind("Ed25519")), storageDirectory, bfv.RotationLeft,k)
			//})
			t.Run(fmt.Sprintf("/TCP/row/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalRotKG(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory, bfv.RotationRow, k)
			})
			t.Run(fmt.Sprintf("/TCP/left/params=%d/nbnodes=%d", 1<<params.LogN, N), func(t *testing.T) {
				testLocalRotKG(t, params, N, onet.NewTCPTest(suites.MustFind("Ed25519")), storageDirectory, bfv.RotationLeft, k)
			})

		}

	}
}

func testLocalRotKG(t *testing.T, params *bfv.Parameters, N int, local *onet.LocalTest, storageDirectory string, rotation bfv.Rotation, k uint64) {

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
	s := ""
	switch rotation {
	case bfv.RotationRow:
		s = fmt.Sprintf("RotationKeyTestRow-%d", params.LogN)
		break
	case bfv.RotationRight:
		s = fmt.Sprintf("RotationKeyTestRight-%d", params.LogN)
		break
	case bfv.RotationLeft:
		s = fmt.Sprintf("RotationKeyTestLeft-%d", params.LogN)
		break
	default:
		t.Fatal("Unknown rotation type.")

	}

	pi, err := local.CreateProtocol(s, tree)
	if err != nil {
		t.Fatal(err)
	}

	rotproto := pi.(*protocols.RotationKeyProtocol)
	log.Lvl1("RTG protocol start ")
	now := time.Now()
	err = rotproto.Start()
	if err != nil {
		log.Error("Could not start rotation ", err)
		t.Fatal(err)
	}

	rotproto.Wait()
	elapsed := time.Since(now)
	log.Lvl1("**********ROTATION KEY PROTOCOL DONE ***************")
	log.Lvl1("**********Time elapsed :", elapsed, "***************")

	rotkey := rotproto.RotKey
	ctxT, _ := ring.NewContextWithParams(1<<params.LogN, []uint64{params.T})
	coeffs := ctxT.NewUniformPoly().Coeffs[0]
	pt := bfv.NewPlaintext(params)
	enc := bfv.NewEncoder(params)
	enc.EncodeUint(coeffs, pt)
	ciphertext := bfv.NewEncryptorFromSk(params, lt.IdealSecretKey0).EncryptNew(pt)
	evaluator := bfv.NewEvaluator(params)
	n := 1 << params.LogN
	mask := uint64(n>>1) - 1
	expected := make([]uint64, n)

	switch rotation {
	case bfv.RotationRow:
		evaluator.RotateRows(ciphertext, &rotkey, ciphertext)
		expected = append(coeffs[n>>1:], coeffs[:n>>1]...)

		break
	case bfv.RotationRight:

		t.Fatal("Not implemented")

	case bfv.RotationLeft:
		evaluator.RotateColumns(ciphertext, k, &rotkey, ciphertext)
		for i := uint64(0); i < uint64(n)>>1; i++ {
			expected[i] = coeffs[(i+k)&mask]
			expected[i+uint64(n>>1)] = coeffs[((i+k)&mask)+uint64(n>>1)]
		}
		break
	}
	resultingPt := bfv.NewDecryptor(params, lt.IdealSecretKey0).DecryptNew(ciphertext)

	decoded := enc.DecodeUint(resultingPt)

	if !utils.Equalslice(expected, decoded) {
		t.Fatal("Decryption failed")
	}

}
