// Simulation for EncToShares protocol. As in the protocol test, global variables (enclosed in
// a dedicated struct) are used to represent the context, that has to be available to different
// goroutines.
// As in test, a random message and its encryption are generated (once per round): the protocol is run on
// the encryption and the result is tested against the message.

package main // TODO: why is this package main?

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

// Implements the onet.Simulation interface. Contains some of the protocol parameters
// that are needed at some point: global variables are still needed.
type EncToSharesSim struct {
	// These parameters will be read from the toml file.
	onet.SimulationBFTree
	ParamsIdx int // TODO: needs to be exported? (probably)

	// These parameters will be initialised in the method NewS after reading the file.
	Params        *bfv.Parameters // TODO: needs to be exported? (probably not)
	sigmaSmudging float64
}

func init() {
	onet.SimulationRegister("EncryptionToShares", NewEncToSharesSim)
}

// Struct holding the global variables representing the context.
// lt is set in Setup, once per test (simulation consists of various tests).
// The other parameters are set in Run, once for each round of every test.
type e2sSimContext struct {
	storageDir string
	lt         *utils.LocalTest
	msg        []uint64
	ct         *bfv.Ciphertext
	accum      *dbfv.ConcurrentAdditiveShareAccum
}

var e2sGlobal = e2sSimContext{storageDir: "tmp/"} // TODO: global variables are horrible

// NewEncToSharesSim is a onet.Simulation factory, registered as a handler with onet.SimulationRegister.
// It reads some parameters from the toml file, and sets others accordingly.
func NewEncToSharesSim(config string) (onet.Simulation, error) {
	log.Lvl1("NewEncToSharesSim called with config = ", config)

	sim := &EncToSharesSim{}

	// The toml file contains ParamsIdx and part of the fields in the SimulationBFTree
	_, err := toml.Decode(config, sim)
	if err != nil {
		log.Fatal("Error decoding toml: ", err)
		return nil, err
	}

	// These parameters can be already set
	sim.Params = bfv.DefaultParams[sim.ParamsIdx]
	sim.sigmaSmudging = sim.Params.Sigma // TODO: set sigmaSmudge

	return sim, nil
}

// Setup is called once per test, only to return the SimulationConfig that will be passed to Node and Run.
// Unfortunately, the Simulation on which it is called is thrown away by onet; the ones on which
// it will call Node are different, and Setup is not called on them. Thus, it is pointless to store
// some context into sim, we have to use global variables.
func (sim *EncToSharesSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	log.Lvl1("Called with hosts = ", hosts)

	// Create tree configuration
	sc := &onet.SimulationConfig{}
	log.Lvl3("Creating Roster and Tree")
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	// Create global LocalTest, that will store key-shards and other relevant parameters.
	log.Lvl3("Creating global LocalTest")
	e2sGlobal.lt, err = utils.GetLocalTestForRoster(sc.Roster, sim.Params, e2sGlobal.storageDir)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// Node is run at each node to set it up, before running the actual protocol.
func (sim *EncToSharesSim) Node(config *onet.SimulationConfig) error {
	log.Lvl1("Node called: starting to set up")

	log.Lvl3("Registering protocol")
	_, err := config.Server.ProtocolRegister("EncryptionToSharesSimul", newE2SSimProtocolFactory(sim))
	if err != nil {
		return errors.New("Error when registering protocol " + err.Error())
	}

	log.Lvl3("Node setup OK")
	return sim.SimulationBFTree.Node(config)
}

// Returns a protocol factory (onet.NewProtocol) that extracts variables (besides tni) from the simulation
// and, alas, the global variables.
func newE2SSimProtocolFactory(sim *EncToSharesSim) onet.NewProtocol {
	return func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		sk := e2sGlobal.lt.SecretKeyShares0[tni.ServerIdentity().ID]
		return protocols.NewEncryptionToSharesProtocol(tni, sim.Params, sim.sigmaSmudging, sk, e2sGlobal.ct,
			protocols.NewE2SAccumFinaliser(e2sGlobal.accum))
	}
}

// Run is executed only at the root. It creates and starts the protocol, then checks for correctness.
// It also computes some timing statistics.
func (sim *EncToSharesSim) Run(config *onet.SimulationConfig) error {
	// Teardown of LocalTest.
	defer func() {
		log.Lvl3("Tearing down LocalTest")
		err := e2sGlobal.lt.TearDown(true)
		if err != nil {
			log.Error("Could not tear down the LocalTest:", err)
		}
	}()

	size := config.Tree.Size()
	log.Lvl1("Called with", size, "nodes; rounds:", sim.Rounds)

	timings := make([]time.Duration, sim.Rounds)
	// TODO: why do we need rounds? We always do the same thing.
	for i := 0; i < sim.Rounds; i++ {
		// Create random msg and its encryption, and allocate AdditiveShare accumulator.
		log.Lvl4("Creating random message and its encryption, allocating accumulator")
		e2sGlobal.msg, e2sGlobal.ct, e2sGlobal.accum = e2sGlobal.lt.GenMsgCtAccum()

		// Create the protocol.
		log.Lvl3("Instantiating protocol")
		pi, err := config.Overlay.CreateProtocol("EncryptionToSharesSimul", config.Tree, onet.NilServiceID) // TODO: why NilServiceID?
		if err != nil {
			log.Fatal("Couldn't create protocol:", err)
		}
		// round := monitor.NewTimeMeasure("alpha") // TODO: is this needed?
		e2sp := pi.(*protocols.EncryptionToSharesProtocol)

		// Launch it in another goroutine.
		log.Lvl1("Starting Encryption-To-Shares protocol in separate goroutine")
		now := time.Now()
		go func() {
			if err = e2sp.Start(); err != nil {
				log.Fatal("Error in protocol Start: ", err)
			}
		}()

		// Wait for completion.
		log.Lvl3("Waiting for protocol to end...")
		e2sGlobal.accum.WaitDone()
		elapsed := time.Since(now)
		timings[i] = elapsed
		log.Lvl1("Elapsed time : ", elapsed)

		//round.Record()

		// Check for correctness.
		if !e2sGlobal.accum.Equal(e2sGlobal.msg) {
			log.Fatal("Sharing error")
		} else {
			log.Lvl1("Sharing successful!")
		}

		// Wait a bit before next round
		<-time.After(1 * time.Second)
	}

	// Compute stats.
	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(sim.Rounds)
	log.Lvl1("Average time: ", avg)

	return nil
}
