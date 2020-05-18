// Simulation for the whole service package

package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service"
	"lattigo-smc/service/messages"
	"lattigo-smc/utils"
	"time"
)

// Implements the onet.Simulation interface.
type SMCSimulation struct {
	onet.SimulationBFTree

	ParamsIdx int
}

func init() {
	onet.SimulationRegister("SMCService", NewSMCSimulation)
}

// NewEncToSharesSim is a onet.Simulation factory, registered as a handler with onet.SimulationRegister.
// It reads some parameters from the toml file.
func NewSMCSimulation(config string) (onet.Simulation, error) {
	log.Lvl1("Called with config =\n", config)

	sim := &SMCSimulation{}

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
func (sim *SMCSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *SMCSimulation) Run(config *onet.SimulationConfig) error {
	size := len(config.Roster.List)
	log.Lvl1("Called with", size, "nodes; rounds:", sim.Rounds)

	// We need 4 servers
	if size < 4 {
		err := errors.New("Called with less than 4 servers")
		log.Error(err)
		return err
	}

	// Setup phase, create clients and session
	clients := make([]*service.Client, 4)

	log.Lvl2("Going to create new session. Should not return error")
	c, sid, mpk, err := simNewClientCreateSession(config.Roster, sim.ParamsIdx, "Simulation-0")
	clients[0] = c
	if err != nil {
		log.Error("Method CreateSession returned error:", err)
		return err
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = clients[0].SendGenEvalKeyQuery(nil)
	if err != nil {
		log.Error("Method SendGenEvalKeyQuery returned error:", err)
		return err
	}
	log.Lvl2("Method SendGenEvalKeyQuery correctly returned no error")

	// Create client 1

	log.Lvl2("Going to bind to session on Client 1. Should not return error")
	c, err = simNewClientBindToSession(config.Roster, 1, sim.ParamsIdx, "Simulation-1", sid, mpk)
	clients[1] = c
	if err != nil {
		log.Error("Method BindToSession on Client 2 returned error:", err)
		return err
	}
	log.Lvl2("Method BindToSession on Client 1 correctly returned no error")

	// Create client 2

	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c, err = simNewClientBindToSession(config.Roster, 2, sim.ParamsIdx, "Simulation-2", sid, mpk)
	clients[2] = c
	if err != nil {
		log.Error("Method BindToSession on Client 2 returned error:", err)
		return err
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Create client 3

	log.Lvl2("Going to bind to session on Client 3. Should not return error")
	c, err = simNewClientBindToSession(config.Roster, 3, sim.ParamsIdx, "Simulation-3", sid, mpk)
	clients[3] = c
	if err != nil {
		log.Error("Method BindToSession on Client 3 returned error:", err)
		return err
	}
	log.Lvl2("Method BindToSession on Client 3 correctly returned no error")

	// Repeat the circuit evaluation many times
	timings := make([]time.Duration, sim.Rounds)
	DoEval := false
	if DoEval {
		for i := 0; i < sim.Rounds; i++ {
			// round := monitor.NewTimeMeasure("alpha") // TODO: is this needed?

			// Generate a0 and b0

			log.Lvl2("Going to generate a0 and b0. Should not return error")
			ctx, a0, b0, err := simGenRandomPolys(sim.ParamsIdx)
			if err != nil {
				log.Error("Could not generate random data:", err)
				return err
			}
			log.Lvl2("Successfully generated random data")

			// Generate a1 and b1

			log.Lvl2("Going to generate a1 and b1. Should not return error")
			ctx, a1, b1, err := simGenRandomPolys(sim.ParamsIdx)
			if err != nil {
				log.Error("Could not generate random data:", err)
				return err
			}
			log.Lvl2("Successfully generated random data")

			// Generate a2 and b2

			log.Lvl2("Going to generate a0 and b0. Should not return error")
			ctx, a2, b2, err := simGenRandomPolys(sim.ParamsIdx)
			if err != nil {
				log.Error("Could not generate random data:", err)
				return err
			}
			log.Lvl2("Successfully generated random data")

			// Generate a3 and b3

			log.Lvl2("Going to generate a3 and b3. Should not return error")
			ctx, a3, b3, err := simGenRandomPolys(sim.ParamsIdx)
			if err != nil {
				log.Error("Could not generate random data:", err)
				return err
			}
			log.Lvl2("Successfully generated random data")

			// Start measuring
			start := time.Now()

			// Store a0

			log.Lvl2("Going to store a0. Should not return error")
			dataA0 := a0.Coeffs[0] // Only one modulus exists
			_, err = clients[0].SendStoreQuery("a", dataA0)
			if err != nil {
				log.Error("Method SendStoreQuery for a0 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for a0 correctly returned no error")

			// Store b0

			log.Lvl2("Going to store b0. Should not return error")
			dataB0 := b0.Coeffs[0] // Only one modulus exists
			_, err = clients[0].SendStoreQuery("b", dataB0)
			if err != nil {
				log.Error("Method SendStoreQuery for b0 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for b0 correctly returned no error")

			// Store a1

			log.Lvl2("Going to store a1. Should not return error")
			dataA1 := a1.Coeffs[0] // Only one modulus exists
			_, err = clients[1].SendStoreQuery("a", dataA1)
			if err != nil {
				log.Error("Method SendStoreQuery for a1 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for a1 correctly returned no error")

			// Store b1

			log.Lvl2("Going to store b1. Should not return error")
			dataB1 := b1.Coeffs[0] // Only one modulus exists
			_, err = clients[1].SendStoreQuery("b", dataB1)
			if err != nil {
				log.Error("Method SendStoreQuery for b1 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for b1 correctly returned no error")

			// Store a2

			log.Lvl2("Going to store a2. Should not return error")
			dataA2 := a2.Coeffs[0] // Only one modulus exists
			_, err = clients[2].SendStoreQuery("a", dataA2)
			if err != nil {
				log.Error("Method SendStoreQuery for a2 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for a2 correctly returned no error")

			// Store b2

			log.Lvl2("Going to store b2. Should not return error")
			dataB2 := b2.Coeffs[0] // Only one modulus exists
			_, err = clients[2].SendStoreQuery("b", dataB2)
			if err != nil {
				log.Error("Method SendStoreQuery for b2 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for b2 correctly returned no error")

			// Store a3

			log.Lvl2("Going to store a3. Should not return error")
			dataA3 := a3.Coeffs[0] // Only one modulus exists
			_, err = clients[3].SendStoreQuery("a", dataA3)
			if err != nil {
				log.Error("Method SendStoreQuery for a3 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for a3 correctly returned no error")

			// Store b3

			log.Lvl2("Going to store b3. Should not return error")
			dataB3 := b3.Coeffs[0] // Only one modulus exists
			_, err = clients[3].SendStoreQuery("b", dataB3)
			if err != nil {
				log.Error("Method SendStoreQuery for b3 returned error:", err)
				return err
			}
			log.Lvl2("Method SendStoreQuery for b3 correctly returned no error")

			// Evaluate the circuit remotely

			log.Lvl2("Going to evaluate the circuit")
			desc := "*(+(+(*(v a@0)(v a@1))(*(v a@1)(v a@2)))(+(*(v a@2)(v a@3))(*(v a@0)(v a@3))))" +
				"(+(+(*(v b@0)(v b@1))(*(v b@1)(v b@2)))(+(*(v b@2)(v b@3))(*(v b@0)(v b@3))))"
			remCirc, err := clients[0].SendCircuitQuery(desc)
			if err != nil {
				log.Error("Method SendCircuitQuery returned error:", err)
				return err
			}
			log.Lvl2("Method SendCircuitQuery correctly returned no error")

			// Stop timer.
			elapsed := time.Since(start)
			timings[i] = elapsed
			log.Lvl1("Elapsed time : ", elapsed)

			//round.Record()

			// Check for correctness.

			// Evaluate the circuit locally
			// ((a0*a1)+(a1*a2)+(a2*a3)+(a0*a3))*((b0*b1)+(b1*b2)+(b2*b3)+(b0*b3))

			log.Lvl2("Going to evaluate the circuit locally")
			// a0*a1
			a0a1 := ctx.NewPoly()
			ctx.MulCoeffs(a0, a1, a0a1)
			// a1*a2
			a1a2 := ctx.NewPoly()
			ctx.MulCoeffs(a1, a2, a1a2)
			// a0*a1+a1*a2
			a0112 := ctx.NewPoly()
			ctx.Add(a0a1, a1a2, a0112)
			// a2*a3
			a2a3 := ctx.NewPoly()
			ctx.MulCoeffs(a2, a3, a2a3)
			// a0*a3
			a0a3 := ctx.NewPoly()
			ctx.MulCoeffs(a0, a3, a0a3)
			// a2*a3+a0*a3
			a2303 := ctx.NewPoly()
			ctx.Add(a2a3, a0a3, a2303)
			// a branch
			a := ctx.NewPoly()
			ctx.Add(a0112, a2303, a)
			// b0*b1
			b0b1 := ctx.NewPoly()
			ctx.MulCoeffs(b0, b1, b0b1)
			// b1*b2
			b1b2 := ctx.NewPoly()
			ctx.MulCoeffs(b1, b2, b1b2)
			// b0*b1+b1*b2
			b0112 := ctx.NewPoly()
			ctx.Add(b0b1, b1b2, b0112)
			// b2*b3
			b2b3 := ctx.NewPoly()
			ctx.MulCoeffs(b2, b3, b2b3)
			// b0*b3
			b0b3 := ctx.NewPoly()
			ctx.MulCoeffs(b0, b3, b0b3)
			// b2*b3+b0*b3
			b2303 := ctx.NewPoly()
			ctx.Add(b2b3, b0b3, b2303)
			// b branch
			b := ctx.NewPoly()
			ctx.Add(b0112, b2303, b)
			// Final result
			locCirc := ctx.NewPoly()
			ctx.MulCoeffs(a, b, locCirc)

			// Test for equality

			log.Lvl2("Going to test for equality. Should be the same")
			if !utils.Equalslice(remCirc, locCirc.Coeffs[0]) {
				err = errors.New("Original result and retrieved result are not the same")
				log.Error(err)
				return err
			}
			log.Lvl2("Original result and retrieved result are the same!")

			// Wait a bit before next round
			<-time.After(1 * time.Second)
		}
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

// Utility methods

var simDefaultSeed []byte = []byte("ZiEtA")

func simNewClientCreateSession(roster *onet.Roster, paramsIdx int, clientID string) (*service.Client,
	messages.SessionID, *bfv.PublicKey, error) {
	client := service.NewClient(roster.List[0], clientID, bfv.DefaultParams[paramsIdx])

	log.Lvl2(client, "Creating session")
	sid, pk, err := client.CreateSession(roster, simDefaultSeed)

	return client, sid, pk, err
}

func simNewClientBindToSession(roster *onet.Roster, srvIdx int, paramsIdx int, clientID string,
	sid messages.SessionID, mpk *bfv.PublicKey) (*service.Client, error) {
	client := service.NewClient(roster.List[srvIdx], clientID, bfv.DefaultParams[paramsIdx])

	log.Lvl2(client, "Binding to session")
	err := client.BindToSession(sid, mpk)

	return client, err
}

func simGenRandomPolys(paramsIdx int) (context *ring.Context, p *ring.Poly, q *ring.Poly, err error) {
	params := bfv.DefaultParams[paramsIdx]
	context, err = ring.NewContextWithParams(uint64(1<<params.LogN), []uint64{params.T})
	if err != nil {
		return
	}

	p = context.NewUniformPoly()
	q = context.NewUniformPoly()
	return
}
