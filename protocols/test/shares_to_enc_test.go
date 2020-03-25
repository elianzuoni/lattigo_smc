// Test for the shares-to-encryption protocol: every node generates its own AdditiveShare, accumulating it
// to the global accumulator, and runs the protocol. Only the root gets the ciphertext, decrypts it and
// checks for consistency with the aggregated AdditiveShare.

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

// Struct containing the global variables representing the context available to all functions and goroutines.
type s2eTestContext struct {
	storageDirectory string
	nbParties        []int
	paramsSets       []*bfv.Parameters
	protoName        string

	params    *bfv.Parameters
	localTest *onet.LocalTest
	lt        *utils.LocalTest
	roster    *onet.Roster
	tree      *onet.Tree

	accum *dbfv.ConcurrentAdditiveShareAccum
	crs   *ring.Poly
}

var s2eTestGlobal = s2eTestContext{
	storageDirectory: "/tmp/",
	nbParties:        []int{3, 8, 16},
	paramsSets:       bfv.DefaultParams,
	protoName:        "SharesToEncryptionTest",
}

// Generates global variables: called once per test.
func s2eTestGenGlobal(params *bfv.Parameters, N int, testType string) {
	var err error

	log.Lvl3("Generating global parameters")

	log.Lvl4("Generating localTest")
	if testType == "local" {
		s2eTestGlobal.localTest = onet.NewLocalTest(suites.MustFind("Ed25519"))
	} else {
		s2eTestGlobal.localTest = onet.NewTCPTest(suites.MustFind("Ed25519"))
	}

	log.Lvl4("Generating roster and tree")
	_, s2eTestGlobal.roster, s2eTestGlobal.tree = s2eTestGlobal.localTest.GenTree(N, true)
	log.Lvl4("Generating lt")
	s2eTestGlobal.lt, err = utils.GetLocalTestForRoster(s2eTestGlobal.roster, params, s2eTestGlobal.storageDirectory)
	if err != nil {
		log.Fatal("Could not generate tree:", err)
	}

	log.Lvl4("Allocating accumulator")
	s2eTestGlobal.accum = dbfv.NewConcurrentAdditiveShareAccum(params, params.Sigma, N)
	log.Lvl4("Generating crs")
	crsGen := dbfv.NewCipherCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	s2eTestGlobal.crs = crsGen.ClockNew()
}

// newProtocolFactory returns a protocol factory respecting the onet.NewProtocol signature.
func s2eTestProtocolFactory(t *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl3("New shares_to_enc protocol instance for", t.ServerIdentity())

	sigmaSmudge := s2eTestGlobal.params.Sigma // TODO: how to set this?
	sk := s2eTestGlobal.lt.SecretKeyShares0[t.ServerIdentity().ID]

	// It is easier to let nodes sample their own AdditiveShare in the protocol factory (instead
	// of setting them in a global look-up map), and then add it to the global accumulator.
	s2e := dbfv.NewS2EProtocol(s2eTestGlobal.params, sigmaSmudge)
	addShare := s2e.GenRandomAddShare()
	s2eTestGlobal.accum.Accumulate(addShare)

	return protocols.NewSharesToEncryptionProtocol(t, s2eTestGlobal.params, sigmaSmudge,
		addShare, sk, s2eTestGlobal.crs)
}

func TestSharesToEncryption(t *testing.T) {
	if testing.Short() {
		s2eTestGlobal.nbParties = s2eTestGlobal.nbParties[:1]
		s2eTestGlobal.paramsSets = s2eTestGlobal.paramsSets[:1]
	}

	log.SetDebugVisible(1)

	log.Lvl3("Registering protocol")
	if _, err := onet.GlobalProtocolRegister(s2eTestGlobal.protoName, s2eTestProtocolFactory); err != nil {
		log.Error("Could not register SharesToEncryptionLocal:", err)
		t.Fail()
	}

	for _, params := range s2eTestGlobal.paramsSets {
		s2eTestGlobal.params = params

		for _, N := range s2eTestGlobal.nbParties {
			// Local test

			log.Lvl4("Generating global context for local test")
			// Generate global context before running protocol
			s2eTestGenGlobal(params, N, "local")

			log.Lvl1("Launching local test")
			localSubTestName := fmt.Sprintf("/local/params=%d/nbParties=%d", 1<<params.LogN, N)
			t.Run(localSubTestName, func(t *testing.T) {
				testS2E(t, N)
			})

			// TCP test

			log.Lvl4("Generating global context for tcp test")
			// Generate global context before running protocol
			s2eTestGenGlobal(params, N, "tcp")

			log.Lvl1("Launching tcp test")
			tcpSubTestName := fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N)
			t.Run(tcpSubTestName, func(t *testing.T) {
				testS2E(t, N)
			})

		}
	}
}

// Acts as root of the protocol: instantiates it, starts it, waits for termination, then checks for correctness.
func testS2E(t *testing.T, N int) {
	log.Lvl1("Started to test shares_to_enc with: ", N, " parties")
	defer s2eTestGlobal.localTest.CloseAll()

	// Instantiate protocol.
	log.Lvl4("Instantiating protocol")
	pi, err := s2eTestGlobal.localTest.CreateProtocol(s2eTestGlobal.protoName, s2eTestGlobal.tree)
	if err != nil {
		t.Fatal("Couldn't instantiate protocol:", err)
	}
	s2e := pi.(*protocols.SharesToEncryptionProtocol)

	// Start protocol
	log.Lvl1("Starting protocol")
	now := time.Now()
	err = s2e.Start()
	if err != nil {
		log.Fatal("Could not start the protocol:", err)
		t.Fail()
	}

	// Wait for termination
	ct := <-s2e.ChannelCiphertext
	elapsed := time.Since(now)
	log.Lvl1("Time elapsed : ", elapsed)

	// Check for correctness
	dec := bfv.NewDecryptor(s2eTestGlobal.params, s2eTestGlobal.lt.IdealSecretKey0)
	plain := bfv.NewPlaintext(s2eTestGlobal.params)
	dec.Decrypt(ct, plain)
	encoder := bfv.NewEncoder(s2eTestGlobal.params)
	msg := encoder.DecodeUint(plain)

	if !s2eTestGlobal.accum.Equal(msg) {
		log.Fatal("Re-encryption failed")
		t.Fail()
	} else {
		log.Lvl1("Re-encryption succeeded!")
	}

	// Tear down lt
	log.Lvl3("Tearing down lt")
	err = s2eTestGlobal.lt.TearDown(false)
	if err != nil {
		log.Fatal(err)
		t.Fail()
	}
}
