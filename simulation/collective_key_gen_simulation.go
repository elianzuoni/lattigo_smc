//This file holds the CKG simulation.
//Contains all method that are implemented in order to implement a protocol from onet.
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
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

type KeyGenerationSim struct {
	onet.SimulationBFTree

	lt *utils.LocalTest

	sk        *bfv.SecretKey
	crp       *ring.Poly
	ParamsIdx int
	Params    *bfv.Parameters
}

func init() {
	onet.SimulationRegister("CollectiveKeyGeneration", NewSimulationKeyGen)
}

var storageDir = "tmp/"
var lt *utils.LocalTest

func NewSimulationKeyGen(config string) (onet.Simulation, error) {
	sim := &KeyGenerationSim{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}
	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

	return sim, nil
}

func (s *KeyGenerationSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//setup following the config file.
	log.Lvl1("Setting up the simulations")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)

	var err error
	s.lt, err = utils.GetLocalTestForRoster(sc.Roster, s.Params, storageDir)
	if err != nil {
		return nil, err
	}
	lt = s.lt

	err = s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *KeyGenerationSim) Node(config *onet.SimulationConfig) error {

	if _, err := config.Server.ProtocolRegister("CollectiveKeyGenerationSimul", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewKeyGenerationSimul(tni, s)
	}); err != nil {
		return errors.New("Error when registering CollectiveKeyGeneration instance " + err.Error())
	}
	s.lt = lt

	// Pre-loading of the secret key at the node
	var found bool
	s.sk, found = s.lt.SecretKeyShares0[config.Server.ServerIdentity.ID]
	if !found {
		return fmt.Errorf("secret key share for %s not found", config.Server.ServerIdentity.ID.String())
	}

	// Pre-initialize the CRP generator
	crsGen := dbfv.NewCRPGenerator(s.Params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	s.crp = crsGen.ClockNew()

	log.Lvl3("Node setup OK")
	return s.SimulationBFTree.Node(config)
}

func NewKeyGenerationSimul(tni *onet.TreeNodeInstance, sim *KeyGenerationSim) (onet.ProtocolInstance, error) {
	//This part allows to injec the data to the node ~ we don't need the messy channels.
	protocol, err := proto.NewCollectiveKeyGeneration(tni)
	if err != nil {
		return nil, err
	}

	// Injects simulation parameters
	colkeygen := protocol.(*proto.CollectiveKeyGenerationProtocol)

	err = colkeygen.Init(sim.Params, sim.sk, sim.crp)
	if err != nil {
		return nil, err
	}

	return colkeygen, nil

}

func (s *KeyGenerationSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	defer func() {
		err := s.lt.TearDown(true)
		if err != nil {
			log.Error("Could not tear down the test. ")
		}
	}()

	log.Lvl3("Size : ", size, " rounds : ", s.Rounds)
	timings := make([]time.Duration, s.Rounds)
	for i := 0; i < s.Rounds; i++ {
		pi, err := config.Overlay.CreateProtocol("CollectiveKeyGenerationSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.Fatal("Couldn't create new node:", err)
		}
		round := monitor.NewTimeMeasure("alpha")
		ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
		log.Lvl1("Starting Collective Key Generation simulation children amt : ", len(ckgp.Children()))
		now := time.Now()
		go func() {
			if err = ckgp.Start(); err != nil {
				log.Fatal("Error in dispatch : ", err)
			}
		}()

		log.Lvl1("waiting..")
		ckgp.Wait()
		elapsed := time.Since(now)
		timings[i] = elapsed
		log.Lvl1("Collective Key Generated for ", len(ckgp.Roster().List), " nodes.")
		log.Lvl1("Elapsed time : ", elapsed)
		//check if we have all the same polys ckg_0
		round.Record()

		//check for correctness here.
		encoder := bfv.NewEncoder(s.Params)
		enc := bfv.NewEncryptorFromPk(s.Params, ckgp.Pk)
		dec := bfv.NewDecryptor(s.Params, s.lt.IdealSecretKey0)
		pt := bfv.NewPlaintext(s.Params)

		ct := enc.EncryptNew(pt)
		ptp := dec.DecryptNew(ct)
		msgp := encoder.DecodeUint(ptp)
		if !utils.Equalslice(pt.Value()[0].Coeffs[0], msgp) {
			log.Error("Decryption failed")
		} else {
			log.Lvl1("Sim ok ")
		}
		<-time.After(1 * time.Second)

	}
	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(s.Rounds)
	log.Lvl1("Average time : ", avg)

	return nil

}
