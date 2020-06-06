package main

import (
	"errors"
	"fmt"
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

	ParamsIdx int
	lt        *utils.LocalTest

	Params *bfv.Parameters
	sk     *bfv.SecretKey
	crs    *ring.Poly
	share  *dbfv.AdditiveShare
}

func init() {
	onet.SimulationRegister("SharesToEncryption", NewSharesToEncSim)
}

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
	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

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

	// Create LocalTest, that will store key-shards and other relevant parameters.
	log.Lvl3("Creating global LocalTest")
	sim.lt, err = utils.GetLocalTestForRoster(sc.Roster, sim.Params, storageDir)
	if err != nil {
		return nil, err
	}

	// Write the local test to file
	err = sim.lt.WriteToFile(dir + "/local_test")
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// Node is run at each node to set it up, before running the actual protocol.
func (sim *SharesToEncSim) Node(config *onet.SimulationConfig) error {
	log.Lvl2("Node called: starting to set up")

	log.Lvl3("Registering protocol")
	_, err := config.Server.ProtocolRegister("SharesToEncryptionSimul", SimNewS2EProto(sim))
	if err != nil {
		return errors.New("Error when registering protocol: " + err.Error())
	}

	// Read the local test from file
	sim.lt = &utils.LocalTest{StorageDirectory: storageDir}
	err = sim.lt.ReadFromFile("local_test")
	if err != nil {
		return err
	}

	// Pre-load the secret key
	var found bool
	sim.sk, found = sim.lt.SecretKeyShares0[config.Server.ServerIdentity.ID]
	if !found {
		return fmt.Errorf("secret key share for %s not found", config.Server.ServerIdentity.ID.String())
	}

	// Pre-load the CRS
	sim.crs = sim.lt.CipherCRS

	// Generate the additive share
	sim.share = dbfv.NewUniformAdditiveShare(sim.Params.LogN, sim.Params.T)

	log.Lvl3("Node Setup OK")
	return sim.SimulationBFTree.Node(config)
}

// Returns a protocol factory (onet.NewProtocol) that extracts variables (besides tni) from the simulation
// and, alas, the global variables. It also creates the node's AdditiveShare.
func SimNewS2EProto(sim *SharesToEncSim) onet.NewProtocol {
	return func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocols.NewSharesToEncryptionProtocol(tni, sim.Params, sim.Params.Sigma, sim.share, sim.sk,
			sim.crs)
	}
}

// Run is executed only at the root. It creates and starts the protocol, then checks for correctness.
// It also computes some timing statistics.
func (sim *SharesToEncSim) Run(config *onet.SimulationConfig) error {
	// Teardown of LocalTest.
	defer func() {
		log.Lvl3("Tearing down LocalTest")
		err := sim.lt.TearDown(true)
		if err != nil {
			log.Error("Could not tear down the LocalTest:", err)
		}
	}()

	size := config.Tree.Size()
	log.Lvl1("Called with", size, "nodes; rounds:", sim.Rounds)

	timings := make([]time.Duration, sim.Rounds)
	for i := 0; i < sim.Rounds; i++ {
		// Create the protocol.
		log.Lvl3("Instantiating protocol")
		pi, err := config.Overlay.CreateProtocol("SharesToEncryptionSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.Fatal("Couldn't create protocol:", err)
		}
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
		s2ep.WaitDone()
		elapsed := time.Since(now)
		timings[i] = elapsed
		log.Lvl1("Elapsed time : ", elapsed)

		// No check for correctness

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
