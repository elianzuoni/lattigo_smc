//This file holds the CKG simulation.
//Contains all method that are implemented in order to implement a protocol from onet.
package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "lattigo-smc/protocols"
	"lattigo-smc/utils"
)

type KeyGenerationSim struct {
	onet.SimulationBFTree
}

func init() {
	onet.SimulationRegister("CollectiveKeyGeneration", NewSimulationKeyGen)
}

var VerifyCorrectness = false

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
	log.Lvl4("Setting up the simulations")
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
	log.Lvl4("Node setup OK")

	return s.SimulationBFTree.Node(config)
}

func NewKeyGenerationSimul(tni *onet.TreeNodeInstance, sim *KeyGenerationSim) (onet.ProtocolInstance, error) {
	//This part allows to injec the data to the node ~ we don't need the messy channels.
	protocol, err := proto.NewCollectiveKeyGeneration(tni)

	if err != nil {
		return nil, err
	}

	//cast
	colkeygen := protocol.(*proto.CollectiveKeyGenerationProtocol)

	if proto.AssignParametersBeforeStart {
		params := bfv.DefaultParams[0]
		sk, err := utils.GetSecretKey(params, tni.ServerIdentity().String())
		if err != nil {
			return nil, err
		}
		colkeygen.Params = *params

		colkeygen.Sk = *sk
	}
	return colkeygen, nil

}

func (s *KeyGenerationSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)

	pi, err := config.Overlay.CreateProtocol("CollectiveKeyGenerationSimul", config.Tree, onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create new node:", err)
	}
	round := monitor.NewTimeMeasure("round")
	ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
	log.Lvl2("Starting Collective Key Generation simulation")
	if err = ckgp.Start(); err != nil {
		return err
	}

	ckgp.Wait()
	log.Lvl1("Collective Key Generated for ", len(ckgp.Roster().List), " nodes.")

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
