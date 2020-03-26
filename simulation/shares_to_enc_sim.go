// Simulation for SharesToEnc protocol. As in the protocol test, global variables (enclosed in
// a dedicated struct) are used to represent the context, that has to be available to different
// goroutines.
// As in test, every node generates its AdditiveShare in the protocol factory and accumulates it
// to a global accumulator, which is eventually used for correctness check.

package main // TODO: why is this package main?

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

// Implements the onet.Simulation interface. Contains some of the protocol parameters
// that are needed at some point: global variables are still needed.
type SharesToEncSim struct {
	// These parameters will be read from the toml file.
	onet.SimulationBFTree
	ParamsIdx int // TODO: needs to be exported? (probably)

	// These parameters will be initialised in the method NewS after reading the file.
	s2e *dbfv.S2EProtocol
}

func init() {
	onet.SimulationRegister("SharesToEncryption", NewSharesToEncSim)
}

// Struct holding the global variables representing the context.
// lt is set in Setup, once per test (simulation consists of various tests).
// The other parameters are set in Run, once for each round of every test.
type s2eSimContext struct {
	storageDir    string
	sigmaSmudging float64
	Params        *bfv.Parameters // TODO: needs to be exported? (probably not)
	lt            *utils.LocalTest
	crs           *ring.Poly
	accum         *dbfv.ConcurrentAdditiveShareAccum
}

var s2eGlobal = s2eSimContext{storageDir: "tmp/"} // TODO: global variables are horrible

// NewSharesToEncSim is a onet.Simulation factory, registered as a handler with onet.SimulationRegister.
// It reads some parameters from the toml file, and sets others accordingly.
func NewSharesToEncSim(config string) (onet.Simulation, error) {
	log.Lvl2("Called with config =\n", config)

	sim := &SharesToEncSim{}

	// The toml file contains ParamsIdx and part of the fields in the SimulationBFTree
	_, err := toml.Decode(config, sim)
	if err != nil {
		log.Fatal("Error decoding toml:", err)
		return nil, err
	}

	// These parameters can be already set
	s2eGlobal.Params = bfv.DefaultParams[sim.ParamsIdx]
	s2eGlobal.sigmaSmudging = s2eGlobal.Params.Sigma // TODO: set sigmaSmudge
	sim.s2e = dbfv.NewS2EProtocol(s2eGlobal.Params, s2eGlobal.sigmaSmudging)

	return sim, nil
}

// Setup is called once per test, only to return the SimulationConfig that will be passed to Node and Run.
// Unfortunately, the Simulation on which it is called is thrown away by onet; the ones on which
// it will call Node are different, and Setup is not called on them. Thus, it is pointless to store
// some context into sim, we have to use global variables.
func (sim *SharesToEncSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	log.Lvl2("Called with hosts = ", hosts)

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
	s2eGlobal.lt, err = utils.GetLocalTestForRoster(sc.Roster, s2eGlobal.Params, s2eGlobal.storageDir)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// Node is run at each node to set it up, before running the actual protocol.
func (sim *SharesToEncSim) Node(config *onet.SimulationConfig) error {
	log.Lvl2("Node called: starting to set up")

	log.Lvl3("Registering protocol")
	_, err := config.Server.ProtocolRegister("SharesToEncryptionSimul", news2eSimProtocolFactory(sim))
	if err != nil {
		return errors.New("Error when registering protocol: " + err.Error())
	}

	log.Lvl3("Node setup OK")
	return sim.SimulationBFTree.Node(config)
}

// Returns a protocol factory (onet.NewProtocol) that extracts variables (besides tni) from the simulation
// and, alas, the global variables. It also creates the node's AdditiveShare.
func news2eSimProtocolFactory(sim *SharesToEncSim) onet.NewProtocol {
	return func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		sk := s2eGlobal.lt.SecretKeyShares0[tni.ServerIdentity().ID]

		// Create own AdditiveShare and accumulate it to the global accumulator
		// (we can't do this in Node, because, when it is called, accum isn't yet defined).
		addShare := sim.s2e.GenRandomAddShare()
		s2eGlobal.accum.Accumulate(addShare)

		return protocols.NewSharesToEncryptionProtocol(tni, s2eGlobal.Params, s2eGlobal.sigmaSmudging, addShare, sk,
			s2eGlobal.crs)
	}
}

// Run is executed only at the root. It creates and starts the protocol, then checks for correctness.
// It also computes some timing statistics.
func (sim *SharesToEncSim) Run(config *onet.SimulationConfig) error {
	// Teardown of LocalTest.
	defer func() {
		log.Lvl3("Tearing down LocalTest")
		err := s2eGlobal.lt.TearDown(true)
		if err != nil {
			log.Error("Could not tear down the LocalTest:", err)
		}
	}()

	size := config.Tree.Size()
	log.Lvl1("Called with", size, "nodes; rounds:", sim.Rounds)

	timings := make([]time.Duration, sim.Rounds)
	// TODO: why do we need rounds? We always do the same thing.
	for i := 0; i < sim.Rounds; i++ {
		// Setting global context.
		log.Lvl4("Generating crs; allocating accumulator")
		s2eGlobal.crs = s2eGlobal.lt.NewCipherCRS()
		s2eGlobal.accum = dbfv.NewConcurrentAdditiveShareAccum(s2eGlobal.lt.Params, s2eGlobal.sigmaSmudging, size)

		// Create the protocol.
		log.Lvl3("Instantiating protocol")
		pi, err := config.Overlay.CreateProtocol("SharesToEncryptionSimul", config.Tree, onet.NilServiceID) // TODO: why NilServiceID?
		if err != nil {
			log.Fatal("Couldn't create protocol:", err)
		}
		// round := monitor.NewTimeMeasure("alpha") // TODO: is this needed?
		s2ep := pi.(*protocols.SharesToEncryptionProtocol)

		// Launch it in another goroutine.
		log.Lvl2("Starting Shares-To-Encryption protocol in separate goroutine")
		now := time.Now()
		go func() {
			if err = s2ep.Start(); err != nil {
				log.Fatal("Error in protocol Start: ", err)
			}
		}()

		// Wait for completion.
		log.Lvl3("Waiting for protocol to end...")
		cipher := <-s2ep.ChannelCiphertext
		elapsed := time.Since(now)
		timings[i] = elapsed
		log.Lvl1("Elapsed time : ", elapsed)

		//round.Record()

		// Check for correctness.
		decryptor := bfv.NewDecryptor(s2eGlobal.Params, s2eGlobal.lt.IdealSecretKey0)
		plain := bfv.NewPlaintext(s2eGlobal.Params)
		decryptor.Decrypt(cipher, plain)
		encoder := bfv.NewEncoder(s2eGlobal.Params)
		msg := encoder.DecodeUint(plain)

		if !s2eGlobal.accum.Equal(msg) {
			log.Fatal("Re-encryption error")
		} else {
			log.Lvl1("Re-encryption successful!")
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
