// Test for the encryption-to-shares protocol: a random message is generated, and the protocol is run on its
// encryption, to test whether the produced additive shares actually add up to the original message.
// Global variables are massively used, to represent context information.

package test

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
	"time"
)

// Struct containing the global variables representing the context available to all functions and goroutines.
type e2sTestContext struct {
	storageDirectory string
	nbParties        []int
	paramsSets       []*bfv.Parameters
	protoName        string

	params    *bfv.Parameters
	localTest *onet.LocalTest
	lt        *utils.LocalTest
	roster    *onet.Roster
	tree      *onet.Tree

	msg   []uint64
	ct    *bfv.Ciphertext
	accum *dbfv.ConcurrentAdditiveShareAccum
}

var e2sTestGlobal = e2sTestContext{
	storageDirectory: "/tmp/",
	nbParties:        []int{3, 8, 16},
	paramsSets:       bfv.DefaultParams,
	protoName:        "EncryptionToSharesTest",
}

// Generates global variables: called once per test.
func e2sTestGenGlobal(params *bfv.Parameters, N int, testType string) {
	var err error

	log.Lvl3("Generating global parameters")

	log.Lvl4("Generating localTest")
	if testType == "local" {
		e2sTestGlobal.localTest = onet.NewLocalTest(suites.MustFind("Ed25519"))
	} else {
		e2sTestGlobal.localTest = onet.NewTCPTest(suites.MustFind("Ed25519"))
	}

	log.Lvl4("Generating roster and tree")
	_, e2sTestGlobal.roster, e2sTestGlobal.tree = e2sTestGlobal.localTest.GenTree(N, true)
	log.Lvl4("Generating lt")
	e2sTestGlobal.lt, err = utils.GetLocalTestForRoster(e2sTestGlobal.roster, params, e2sTestGlobal.storageDirectory)
	if err != nil {
		log.Fatal("Could not generate lt:", err)
	}

	log.Lvl4("Generating random message and its encryption; allocating accumulator")
	e2sTestGlobal.msg, e2sTestGlobal.ct, e2sTestGlobal.accum = e2sTestGlobal.lt.GenMsgCtAccum()
}

// e2sTestProtocolFactory is a protocol factory respecting the onet.NewProtocol signature: it supplies
// additional arguments to the NewEncryptionToSharesProtocol constructor by taking them from the global context.
func e2sTestProtocolFactory(t *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl3("new enc_to_shares protocol instance for", t.ServerIdentity())

	sigmaSmudge := e2sTestGlobal.params.Sigma // TODO: how to set this?
	sk := e2sTestGlobal.lt.SecretKeyShares0[t.ServerIdentity().ID]

	return protocols.NewEncryptionToSharesProtocol(t, e2sTestGlobal.params, sigmaSmudge,
		sk, e2sTestGlobal.ct, protocols.NewE2SAccumFinaliser(e2sTestGlobal.accum))
}

func TestEncryptionToShares(t *testing.T) {
	if testing.Short() {
		e2sTestGlobal.nbParties = e2sTestGlobal.nbParties[:1]
		e2sTestGlobal.paramsSets = e2sTestGlobal.paramsSets[:1]
	}

	log.SetDebugVisible(1)

	log.Lvl3("Registering protocol")
	if _, err := onet.GlobalProtocolRegister(e2sTestGlobal.protoName, e2sTestProtocolFactory); err != nil {
		log.Fatal("Could not register protocol:", err)
		t.Fail()
	}

	for _, params := range e2sTestGlobal.paramsSets {
		e2sTestGlobal.params = params

		for _, N := range e2sTestGlobal.nbParties {
			// Local test

			log.Lvl4("Generating global context for local test")
			// Generate global context before running protocol
			e2sTestGenGlobal(params, N, "local")

			log.Lvl1("Launching local test")
			localSubTestName := fmt.Sprintf("/local/params=%d/nbParties=%d", 1<<params.LogN, N)
			t.Run(localSubTestName, func(t *testing.T) {
				testE2S(t, N)
			})

			// TCP test

			// Generate global context before running protocol
			log.Lvl4("Generating global context for tcp test")
			e2sTestGenGlobal(params, N, "tcp")

			log.Lvl1("Launching tcp test")
			tcpSubTestName := fmt.Sprintf("/TCP/params=%d/nbnodes=%d", 1<<params.LogN, N)
			t.Run(tcpSubTestName, func(t *testing.T) {
				testE2S(t, N)
			})

		}
	}
}

// Acts as root of the protocol: instantiates it, starts it, waits for termination, then checks for correctness.
func testE2S(t *testing.T, N int) {
	log.Lvl1("Started to test enc_to_shares with: ", N, " parties")
	defer e2sTestGlobal.localTest.CloseAll()

	// Instantiate protocol.
	log.Lvl4("Instantiating protocol")
	pi, err := e2sTestGlobal.localTest.CreateProtocol(e2sTestGlobal.protoName, e2sTestGlobal.tree)
	if err != nil {
		t.Fatal("Couldn't instantiate protocol:", err)
	}
	e2s := pi.(*protocols.EncryptionToSharesProtocol)

	// Start protocol.
	log.Lvl1("Starting protocol")
	now := time.Now()
	err = e2s.Start()
	if err != nil {
		log.Fatal("Could not start the protocol : ", err)
		t.Fail()
	}

	// Wait for termination.
	log.Lvl3("Waiting for protocol termination...")
	e2sTestGlobal.accum.WaitDone()
	elapsed := time.Since(now)
	log.Lvl1("Time elapsed : ", elapsed)

	// Check for correctness.
	if !e2sTestGlobal.accum.Equal(e2sTestGlobal.msg) {
		log.Fatal("Sharing failed")
		t.Fail()
	}
	log.Lvl1("Sharing succeeded!")

	// Tear down lt
	log.Lvl3("Tearing down lt")
	err = e2sTestGlobal.lt.TearDown(false)
	if err != nil {
		log.Fatal(err)
		t.Fail()
	}
}
