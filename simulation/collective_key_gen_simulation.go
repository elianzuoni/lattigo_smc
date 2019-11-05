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
	log.Lvl1("Setting up the simulations")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *KeyGenerationSim) Node(config *onet.SimulationConfig) error {
	log.Lvl1("B")
	//idx, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	//if idx < 0 {
	//	log.Fatal("Error node not found")
	//}

	if _, err := config.Server.ProtocolRegister("CollectiveKeyGenerationSimul",func(tni *onet.TreeNodeInstance)(onet.ProtocolInstance,error){
		return NewKeyGenerationSimul(tni,s)
	});err != nil{
		return errors.New("Error when registering CollectiveKeyGeneration instance " + err.Error())
	}
	log.Lvl1("Node setup")

	return s.SimulationBFTree.Node(config)
}

func NewKeyGenerationSimul(tni *onet.TreeNodeInstance, sim *KeyGenerationSim) (onet.ProtocolInstance, error) {
	//This part allows to injec the data to the node ~ we don't need the messy channels.
	protocol , err := proto.NewCollectiveKeyGeneration(tni)
	log.Lvl1("HIII")

	if err != nil{
		return nil, err
	}

	//cast
	colkeygen := protocol.(*proto.CollectiveKeyGenerationProtocol)
	colkeygen.Params = bfv.DefaultParams[0]
	return colkeygen, nil

}

func (s *KeyGenerationSim) Run(config *onet.SimulationConfig) error {
	log.Lvl1("A")
	size := config.Tree.Size()


	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)

	round := monitor.NewTimeMeasure("round")


	pi, err := config.Overlay.CreateProtocol("CollectiveKeyGenerationSimul", config.Tree, onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create new node:", err)
	}

	ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
	log.Lvl1("Starting Collective Key Generation simulation")
	if err = ckgp.Start(); err != nil{
		return err
	}

	log.Lvl1("Collective Key Generated for ", len(ckgp.Roster().List), " nodes.\n\tNow comparing all polynomials.")
	<-ckgp.ProtocolInstance().(*proto.CollectiveKeyGenerationProtocol).ChannelParams
	//check if we have all the same polys ckg_0
	CheckKeys(ckgp, err)
	round.Record()
	if err != nil {
		log.Fatal("Could not start the tree : ", err)
	}

	log.Lvl1("finished")
	return nil

}

func CheckKeys(ckgp *proto.CollectiveKeyGenerationProtocol, err error) {
	keys := make([]bfv.PublicKey, len(ckgp.Roster().List))
	ctx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	for i := 0; i < len(ckgp.Roster().List); i++ {
		//get the keys.
		seed := (*ckgp.List()[i].ServerIdentity).String()

		key, _ := utils.LoadPublicKey(ctx, seed)
		keys[i] = *key
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
