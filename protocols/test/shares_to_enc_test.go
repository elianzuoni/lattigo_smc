// Test for the shares-to-encryption protocol: every node generates its own AdditiveShare, accumulating it
// to the global accumulator, and runs the protocol. Only the root gets the ciphertext, decrypts it and
// check for consistency with the aggregated AdditiveShare.

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
	"testing"
	"time"
)

type s2eTestContext struct {
	storageDirectory string
	nbParties        []int
	paramsSets       []*bfv.Parameters

	localTest *onet.LocalTest
	lt        *utils.LocalTest
	roster    *onet.Roster
	tree      *onet.Tree
	protoName string

	accum *concurrentAdditiveShareAccum
	crs   *ring.Poly
}

var s2eTestGlobal = s2eTestContext{
	storageDirectory: "/tmp/",
	nbParties:        []int{3, 8, 16},
	paramsSets:       bfv.DefaultParams,
}

// lt, accum, and crs are not yet defined when newProtocolFactory is called, so it cannot hardcode them
// into the protocol factory. Since the protocol factory will only use them when they are defined,
// getter methods solve the problem.
func s2eTestGetLt() *utils.LocalTest {
	return s2eTestGlobal.lt
}
func s2eTestGetCrp() *ring.Poly {
	return s2eTestGlobal.crs
}
func s2eTestGetAccum() *concurrentAdditiveShareAccum {
	return s2eTestGlobal.accum
}

func s2eTestGenGlobal(params *bfv.Parameters, N int, testType string) {
	var err error

	if testType == "local" {
		s2eTestGlobal.localTest = onet.NewLocalTest(suites.MustFind("Ed25519"))
	} else {
		s2eTestGlobal.localTest = onet.NewTCPTest(suites.MustFind("Ed25519"))
	}

	_, s2eTestGlobal.roster, s2eTestGlobal.tree = s2eTestGlobal.localTest.GenTree(N, true)
	s2eTestGlobal.lt, err = utils.GetLocalTestForRoster(s2eTestGlobal.roster, params, s2eTestGlobal.storageDirectory)
	if err != nil {
		log.Fatal("Could not generate tree:", err)
	}

	s2eTestGlobal.accum = newConcurrentAdditiveShareAccum(params, params.Sigma, N)
	crsGen := dbfv.NewCipherCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	s2eTestGlobal.crs = crsGen.ClockNew()
}

// newProtocolFactory returns a protocol factory respecting the onet.NewProtocol signature.
func newS2ETestProtocolFactory(params *bfv.Parameters) func(*onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	return func(t *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		log.Lvl3("new shares_to_enc protocol instance for", t.ServerIdentity())

		sigmaSmudge := params.Sigma // TODO: how to set this?
		sk := s2eTestGetLt().SecretKeyShares0[t.ServerIdentity().ID]
		s2e := dbfv.NewS2EProtocol(params, sigmaSmudge)
		addShare := s2e.GenRandomAddShare()
		s2eTestGetAccum().accumulate(addShare)

		return protocols.NewSharesToEncryptionProtocol(t, params, sigmaSmudge, addShare, sk, s2eTestGetCrp())
	}
}

func TestSharesToEncryption(t *testing.T) {
	if testing.Short() {
		s2eTestGlobal.nbParties = s2eTestGlobal.nbParties[:1]
		s2eTestGlobal.paramsSets = s2eTestGlobal.paramsSets[:1]
	}

	log.SetDebugVisible(1)

	// Every triple (parameter set, roster size, test type) defines a different protocol, with its name and factory
	for _, params := range s2eTestGlobal.paramsSets {
		for _, N := range s2eTestGlobal.nbParties {
			// Local test
			s2eTestGlobal.protoName = fmt.Sprintf("SharesToEncryptionLocal-%d-%d_nodes", params.LogN, N)
			protoFactory := newS2ETestProtocolFactory(params)

			if _, err := onet.GlobalProtocolRegister(s2eTestGlobal.protoName, protoFactory); err != nil {
				log.Error("Could not register SharesToEncryptionLocal : ", err)
				t.Fail()
			}

			// genGlobal starts the servers, so it needs to be called after registering protocols
			s2eTestGenGlobal(params, N, "local")

			localSubTestName := fmt.Sprintf("/local/params=%d/nbParties=%d", 1<<params.LogN, N)
			t.Run(localSubTestName, func(t *testing.T) {
				testS2E(t, params, N)
			})

			// TCP test

			s2eTestGlobal.protoName = fmt.Sprintf("SharesToEncryptionTCP-%d-%d_nodes", params.LogN, N)
			protoFactory = newS2ETestProtocolFactory(params)

			if _, err := onet.GlobalProtocolRegister(s2eTestGlobal.protoName, protoFactory); err != nil {
				log.Error("Could not register SharesToEncryptionTCP : ", err)
				t.Fail()
			}

			// genGlobal starts the servers, so it needs to be called after registering protocols
			s2eTestGenGlobal(params, N, "tcp")

			tcpSubTestName := fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N)
			t.Run(tcpSubTestName, func(t *testing.T) {
				testS2E(t, params, N)
			})

		}
	}
}

func testS2E(t *testing.T, params *bfv.Parameters, N int) {
	log.Lvl1("Started to test shares_to_enc with: ", N, " parties")
	defer s2eTestGlobal.localTest.CloseAll()

	// The protocol has already been registered under protoName: current thread acts as root.
	pi, err := s2eTestGlobal.localTest.CreateProtocol(s2eTestGlobal.protoName, s2eTestGlobal.tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}
	s2e := pi.(*protocols.SharesToEncryptionProtocol)

	log.Lvl1("Starting s2e")
	now := time.Now()
	err = s2e.Start()
	if err != nil {
		log.Fatal("Could not start the protocol : ", err)
		t.Fail()
	}

	s2eTestGlobal.accum.waitDone()
	ct := <-s2e.ChannelCiphertext
	elapsed := time.Since(now)
	log.Lvl1("**********Done! Time elapsed : ", elapsed, "*************")

	dec := bfv.NewDecryptor(params, s2eTestGlobal.lt.IdealSecretKey0)
	plain := bfv.NewPlaintext(params)
	dec.Decrypt(ct, plain)
	encoder := bfv.NewEncoder(params)
	msg := encoder.DecodeUint(plain)

	if !s2eTestGlobal.accum.Equal(msg) {
		log.Fatal("Re-encryption failed")
		t.Fail()
	}

	err = s2eTestGlobal.lt.TearDown(false)
	if err != nil {
		log.Fatal(err)
		t.Fail()
	}

	log.Lvl1("Success")
}
