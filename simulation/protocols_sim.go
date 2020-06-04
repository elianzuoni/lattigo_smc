// Simulation for the single protocols

package main

import (
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service"
	"lattigo-smc/utils"
	"time"
)

// Implements the onet.Simulation interface.
type ProtocolsSimulation struct {
	onet.SimulationBFTree

	ParamsIdx int
	Pause     int
}

func init() {
	onet.SimulationRegister("Protocols", NewProtocolsSimulation)
}

// NewProtocolsSimulation is a onet.Simulation factory, registered as a handler with onet.SimulationRegister.
// It reads some parameters from the toml file.
func NewProtocolsSimulation(config string) (onet.Simulation, error) {
	log.Lvl1("Called with config =\n", config)

	sim := &ProtocolsSimulation{}

	// The toml file contains part of the fields in the SimulationBFTree
	_, err := toml.Decode(config, sim)
	if err != nil {
		log.Fatal("Error decoding toml: ", err)
		return nil, err
	}

	return sim, nil
}

// Setup is called once per test, only to return the SimulationConfig that will be passed to Node and Run.
// Unfortunately, the Simulation on which it is called is thrown away by onet; the ones on which
// it will call Node are different, and Setup is not called on them. Thus, it is pointless to store
// some context into sim.
func (sim *ProtocolsSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	log.Lvl1("Called with hosts = ", hosts)

	// Create tree configuration
	sc := &onet.SimulationConfig{}
	log.Lvl3("Creating Roster and Tree")
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// Run is executed only at the root.
func (sim *ProtocolsSimulation) Run(config *onet.SimulationConfig) error {
	size := len(config.Roster.List)
	log.Lvl1("Called with", size, "nodes; rounds:", sim.Rounds)

	// We need 3 servers
	if size < 3 {
		err := errors.New("Called with less than 4 servers")
		log.Error(err)
		return err
	}

	// Create client
	log.Lvl2("Going to create new client")
	c := service.NewClient(config.Roster.List[0], "DioClient", bfv.DefaultParams[sim.ParamsIdx])

	// Initialise the timings structure
	timings := make(map[string][]time.Duration)
	timings["PublicKeyGen"] = make([]time.Duration, sim.Rounds)
	timings["EvalKeyGen"] = make([]time.Duration, sim.Rounds)
	timings["RotationKeyGen"] = make([]time.Duration, sim.Rounds)
	timings["EncToShares"] = make([]time.Duration, sim.Rounds)
	timings["SharesToEnc"] = make([]time.Duration, sim.Rounds)
	timings["Refresh"] = make([]time.Duration, sim.Rounds)
	timings["PublicKeySwitch"] = make([]time.Duration, sim.Rounds)

	// Repeat the protocols execution many times
	var start time.Time
	for i := 0; i < sim.Rounds; i++ {
		// Create session and generate public key

		log.Lvl2("Going to create session. Should not return error")
		start = time.Now()
		_, _, err := c.CreateSession(config.Roster, nil)
		timings["PublicKeyGen"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not create session:", err)
			return err
		}
		log.Lvl2("Successfully created session")

		// Generate evaluation key

		log.Lvl2("Going to generate evaluation key. Should not return error")
		start = time.Now()
		err = c.SendGenEvalKeyQuery(nil)
		timings["EvalKeyGen"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not generate evaluation key:", err)
			return err
		}
		log.Lvl2("Successfully generated evaluation key")

		// Generate rotation key

		log.Lvl2("Going to generate rotation key. Should not return error")
		start = time.Now()
		err = c.SendGenRotKeyQuery(bfv.RotationLeft, 77, nil)
		timings["RotationKeyGen"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not generate rotation key:", err)
			return err
		}
		log.Lvl2("Successfully generated rotation key")

		// Generate random data

		log.Lvl2("Going to generate random data. Should not return error")
		_, p, _, err := simGenRandomPolys(sim.ParamsIdx)
		if err != nil {
			log.Error("Could not generate random data:", err)
			return err
		}
		log.Lvl2("Successfully generated random data")

		// Store m

		log.Lvl2("Going to store p. Should not return error")
		cid, err := c.SendStoreQuery(p.Coeffs[0])
		if err != nil {
			log.Error("Method SendStoreQuery returned error:", err)
			return err
		}
		log.Lvl2("Method SendStoreQuery correctly returned no error")

		// Share the ciphertext

		log.Lvl2("Going to share the ciphertext. Should not return error")
		start = time.Now()
		shid, err := c.SendEncToSharesQuery(cid)
		timings["EncToShares"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not share the ciphertext:", err)
			return err
		}
		log.Lvl2("Successfully shared the ciphertext")

		// Re-encrypt the shares

		log.Lvl2("Going to re-encrypt. Should not return error")
		start = time.Now()
		cid, err = c.SendSharesToEncQuery(shid, nil)
		timings["SharesToEnc"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not re-encrypt the shares:", err)
			return err
		}
		log.Lvl2("Successfully re-encrypted the shares")

		// Refresh the ciphertext

		log.Lvl2("Going to refresh the ciphertext. Should not return error")
		start = time.Now()
		cid, err = c.SendRefreshQuery(cid, nil)
		timings["Refresh"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not refresh the ciphertext:", err)
			return err
		}
		log.Lvl2("Successfully refreshed the ciphertext")

		// Switch the ciphertext and decrypt

		log.Lvl2("Going to switch the ciphertext and decrypt. Should not return error")
		start = time.Now()
		m, err := c.SendSwitchQuery(cid)
		timings["PublicKeySwitch"][i] = time.Since(start)
		if err != nil {
			log.Error("Could not switch the ciphertext and decrypt it:", err)
			return err
		}
		log.Lvl2("Successfully switched the ciphertext and decrypted it")

		// Check for equality
		if !utils.Equalslice(m, p.Coeffs[0]) {
			err = errors.New("Original and retrieved data do not coincide")
			log.Error(err)
			return err
		}
		log.Lvl1("Original and retrieved data match!")

		// Close the session
		log.Lvl2("Going to close the session. Should not return error")
		err = c.CloseSession()
		if err != nil {
			log.Error("Could not close the session:", err)
			return err
		}
		log.Lvl2("Successfully closed the session")

		// Wait a bit before next round
		<-time.After(time.Duration(sim.Pause) * time.Second)
	}

	fmt.Print("\n******************************* END OF SIMULATION *******************************\n\n")

	// Compute stats.
	for protoName, times := range timings {
		log.Lvl1("Protocol:", protoName)
		avg := time.Duration(0)
		for i, t := range times {
			log.Lvl1("Elapsed time at round", i, ":", t)
			avg += t
		}
		avg /= time.Duration(sim.Rounds)
		log.Lvl1("Average:", avg, "\n")
	}

	return nil
}
