//This file holds the CKG simulation.
//Contains all method that are implemented in order to implement a protocol from onet.
package main

import (
	"errors"
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

	sk *bfv.SecretKey
	crp *ring.Poly
}

func init() {
	onet.SimulationRegister("CollectiveKeyGeneration", NewSimulationKeyGen)
}

var VerifyCorrectness = false
var params = bfv.DefaultParams[1]

func NewSimulationKeyGen(config string) (onet.Simulation, error) {
	sim := &KeyGenerationSim{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

func (s *KeyGenerationSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//setup following the config file.
	log.Lvl3("Setting up the simulations")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
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

	// Pre-loading of the secret key at the node
	var err error
	s.sk, err = utils.GetSecretKey(params, config.Server.ServerIdentity.String())
	if err != nil {
		return err
	}

	// Pre-initialize the CRP generator
	crsGen := dbfv.NewCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
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
	err = colkeygen.Init(params, sim.sk, sim.crp)
	if err != nil {
		return nil, err
	}

	return colkeygen, nil

}

func (s *KeyGenerationSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl3("Size : ", size, " rounds : ", s.Rounds)

	pi, err := config.Overlay.CreateProtocol("CollectiveKeyGenerationSimul", config.Tree, onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create new node:", err)
	}
	round := monitor.NewTimeMeasure("round")
	ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
	log.Lvl2("Starting Collective Key Generation simulation")
	now := time.Now()
	if err = ckgp.Start(); err != nil {
		return err
	}

	ckgp.Wait()
	elapsed := time.Since(now)
	log.Lvl1("Collective Key Generated for ", len(ckgp.Roster().List), " nodes.")
	log.Lvl1("Elapsed time : ", elapsed)
	//check if we have all the same polys ckg_0
	round.Record()

	if VerifyCorrectness {
		CheckKeys(ckgp, err)
		if err != nil {
			log.Fatal("Could not start the tree : ", err)
		}
	}

	return nil

}

/*****************UTILITY FOR VERIFYING KEYS *****/
func CheckKeys(ckgp *proto.CollectiveKeyGenerationProtocol, err error) {
	keys := make([]bfv.PublicKey, len(ckgp.Roster().List))
	for i := 0; i < len(ckgp.Roster().List); i++ {

		keys[i] = (<-ckgp.ChannelPublicKey).PublicKey
	}

	for _, k1 := range keys {
		for _, k2 := range keys {
			err := utils.CompareKeys(k1, k2)
			if err != nil {
				log.Error("Error in polynomial comparison : ", err)
			}
		}
	}
}
