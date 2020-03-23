// Test for the encryption-to-shares protocol: a random message is generated, and the protocol is run on its
// encryption, to test whether the produced additive shares actually add up to the original message.
// Global variables are massively used, to represent context information.

package test

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"sync"
	"testing"
	"time"
)

// Various goroutines, each running the protocol as a node, will need to provide their AdditiveShare to
// a common accumulator. The last one unlocks "done", awaking the master thread.
type concurrentAdditiveShareAccum struct {
	*sync.Mutex
	*dbfv.AdditiveShare
	proto   *dbfv.E2SProtocol
	missing int
	done    *sync.Mutex
}

func newConcurrentAdditiveShareAccum(params *bfv.Parameters, sigmaSmudging float64, nbParties int) *concurrentAdditiveShareAccum {
	proto := dbfv.NewE2SProtocol(params, sigmaSmudging)
	c := &concurrentAdditiveShareAccum{
		Mutex:         &sync.Mutex{},
		AdditiveShare: proto.AllocateAddShare(),
		proto:         proto,
		missing:       nbParties,
		done:          &sync.Mutex{},
	}

	c.done.Lock()
	return c
}

func (accum *concurrentAdditiveShareAccum) accumulate(share *dbfv.AdditiveShare) {
	accum.Lock()
	defer accum.Unlock()

	accum.proto.SumAdditiveShares(accum.AdditiveShare, share, accum.AdditiveShare)
	accum.missing -= 1
	if accum.missing == 0 {
		accum.done.Unlock()
	}
}

func (accum *concurrentAdditiveShareAccum) waitDone() {
	accum.done.Lock()
}

// finaliser accumulates to the global accumulator.
func finaliser(share *dbfv.AdditiveShare) {
	e2sTestGlobal.accum.accumulate(share)

}

type e2sTestContext struct {
	storageDirectory string
	nbParties        []int
	paramsSets       []*bfv.Parameters

	localTest *onet.LocalTest
	lt        *utils.LocalTest
	roster    *onet.Roster
	tree      *onet.Tree
	protoName string

	msg   []uint64
	ct    *bfv.Ciphertext
	accum *concurrentAdditiveShareAccum
}

var e2sTestGlobal = e2sTestContext{
	storageDirectory: "/tmp/",
	nbParties:        []int{3, 8, 16},
	paramsSets:       bfv.DefaultParams,
}

// lt, and ct are not yet defined when newProtocolFactory is called, so it cannot hardcode them
// into the protocol factory. Since the protocol factory will only use them when they are defined,
// getter methods solve the problem.
func e2sTestGetLt() *utils.LocalTest {
	return e2sTestGlobal.lt
}
func e2sTestGetCt() *bfv.Ciphertext {
	return e2sTestGlobal.ct
}

func e2sTestGenGlobal(params *bfv.Parameters, N int, testType string) {
	var err error

	if testType == "local" {
		e2sTestGlobal.localTest = onet.NewLocalTest(suites.MustFind("Ed25519"))
	} else {
		e2sTestGlobal.localTest = onet.NewTCPTest(suites.MustFind("Ed25519"))
	}

	_, e2sTestGlobal.roster, e2sTestGlobal.tree = e2sTestGlobal.localTest.GenTree(N, true)
	e2sTestGlobal.lt, err = utils.GetLocalTestForRoster(e2sTestGlobal.roster, params, e2sTestGlobal.storageDirectory)
	if err != nil {
		log.Fatal("Could not generate tree:", err)
	}

	n := uint64(1 << params.LogN)
	contextT, _ := ring.NewContextWithParams(n, []uint64{params.T})

	poly := contextT.NewUniformPoly()
	e2sTestGlobal.msg = poly.Coeffs[0]
	encoder := bfv.NewEncoder(params)
	plain := bfv.NewPlaintext(params)
	encoder.EncodeUint(e2sTestGlobal.msg, plain)
	e2sTestGlobal.ct = bfv.NewCiphertext(params, 1)
	encryptor := bfv.NewEncryptorFromSk(params, e2sTestGlobal.lt.IdealSecretKey0)
	encryptor.Encrypt(plain, e2sTestGlobal.ct)

	e2sTestGlobal.accum = newConcurrentAdditiveShareAccum(params, params.Sigma, N)
}

// newProtocolFactory returns a protocol factory respecting the onet.NewProtocol signature.
func newE2STestProtocolFactory(params *bfv.Parameters, finalise func(*dbfv.AdditiveShare)) func(*onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	return func(t *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		log.Lvl3("new enc_to_shares protocol instance for", t.ServerIdentity())

		sigmaSmudge := params.Sigma // TODO: how to set this?
		sk := e2sTestGetLt().SecretKeyShares0[t.ServerIdentity().ID]

		return protocols.NewEncryptionToSharesProtocol(t, params, sigmaSmudge, sk, e2sTestGetCt(), finalise)
	}
}

func TestEncryptionToShares(t *testing.T) {
	if testing.Short() {
		e2sTestGlobal.nbParties = e2sTestGlobal.nbParties[:1]
		e2sTestGlobal.paramsSets = e2sTestGlobal.paramsSets[:1]
	}

	log.SetDebugVisible(1)

	// Every triple (parameter set, roster size, test type) defines a different protocol, with its name and factory
	for _, params := range e2sTestGlobal.paramsSets {
		for _, N := range e2sTestGlobal.nbParties {
			// Local test
			e2sTestGlobal.protoName = fmt.Sprintf("EncryptionToSharesLocal-%d-%d_nodes", params.LogN, N)
			protoFactory := newE2STestProtocolFactory(params, finaliser)

			if _, err := onet.GlobalProtocolRegister(e2sTestGlobal.protoName, protoFactory); err != nil {
				log.Error("Could not register EncryptionToSharesLocal : ", err)
				t.Fail()
			}

			// genGlobal starts the servers, so it needs to be called after registering protocols
			e2sTestGenGlobal(params, N, "local")

			localSubTestName := fmt.Sprintf("/local/params=%d/nbParties=%d", 1<<params.LogN, N)
			t.Run(localSubTestName, func(t *testing.T) {
				testE2S(t, params, N)
			})

			// TCP test

			e2sTestGlobal.protoName = fmt.Sprintf("EncryptionToSharesTCP-%d-%d_nodes", params.LogN, N)
			protoFactory = newE2STestProtocolFactory(params, finaliser)

			if _, err := onet.GlobalProtocolRegister(e2sTestGlobal.protoName, protoFactory); err != nil {
				log.Error("Could not register EncryptionToSharesTCP : ", err)
				t.Fail()
			}

			// genGlobal starts the servers, so it needs to be called after registering protocols
			e2sTestGenGlobal(params, N, "tcp")

			tcpSubTestName := fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N)
			t.Run(tcpSubTestName, func(t *testing.T) {
				testE2S(t, params, N)
			})

		}
	}
}

func testE2S(t *testing.T, params *bfv.Parameters, N int) {
	log.Lvl1("Started to test enc_to_shares with: ", N, " parties")
	defer e2sTestGlobal.localTest.CloseAll()

	// The protocol has already been registered under protoName: current thread acts as root.
	pi, err := e2sTestGlobal.localTest.CreateProtocol(e2sTestGlobal.protoName, e2sTestGlobal.tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}
	e2s := pi.(*protocols.EncryptionToSharesProtocol)

	log.Lvl1("Starting e2s")
	now := time.Now()
	err = e2s.Start()
	if err != nil {
		log.Fatal("Could not start the protocol : ", err)
		t.Fail()
	}

	e2sTestGlobal.accum.waitDone()
	elapsed := time.Since(now)
	log.Lvl1("**********Done! Time elapsed : ", elapsed, "*************")

	if !e2sTestGlobal.accum.Equal(e2sTestGlobal.msg) {
		log.Fatal("Sharing failed")
		t.Fail()
	}

	err = e2sTestGlobal.lt.TearDown(false)
	if err != nil {
		log.Fatal(err)
		t.Fail()
	}

	log.Lvl1("Success")
}
