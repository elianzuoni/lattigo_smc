package simulation

import (
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "protocols/protocols"
)

type KeyGenerationSim struct {
	onet.SimulationBFTree
}

func init(){
	onet.SimulationRegister("KeyGenerationSim",NewSimulationKeyGen)
}

func NewSimulationKeyGen(config string)(onet.Simulation, error){
	sim := &KeyGenerationSim{}

	_,err := toml.Decode(config,sim)
	if err != nil{
		return nil,err
	}

	return sim,nil
}

func (s* KeyGenerationSim) Setup(dir string,hosts []string)(*onet.SimulationConfig,error){
	//setup following the config file.
	log.Lvl1("Setting up the simulations")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc,hosts,2000)
	err := s.CreateTree(sc)
	if err != nil{
		return nil, err
	}
	return sc,nil
}

func (s* KeyGenerationSim) Node(config *onet.SimulationConfig)error{
	idx , _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	log.Lvl1("Node setup")

	return s.SimulationBFTree.Node(config)
}

func (s *KeyGenerationSim)Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl1("Size : " , size, " rounds : " , s.Rounds)
	//for round := 0; round < s.Rounds; round ++{
	//	round := monitor.NewTimeMeasure("round")
	//	pi,err := config.Overlay.CreateProtocol("KeyGenerationSim",config.Tree,onet.NilServiceID)
	//
	//	if err != nil {
	//		log.Fatal("Couldn't create new node:", err)
	//	}
	//
	//	ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
	//	ckgp.Params = bfv.DefaultParams[0]
	//	log.Lvl1("Starting ckgp")
	//	err = ckgp.Start()
	//
	//	ckg_0 := (<-ckgp.ChannelPublicKey).Poly
	//
	//
	//	log.Lvl1("Public key is : " ,ckg_0)
	//	round.Record()
	//	if err != nil{
	//		log.Fatal("Could not start the tree : " , err)
	//	}
	//}
	round := monitor.NewTimeMeasure("round")

	//TODO what is the service ID ?
	pi,err := config.Overlay.StartProtocol("KeyGenerationSim",config.Tree,onet.NilServiceID)
		if err != nil {
			log.Fatal("Couldn't create new node:", err)
		}

		ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
		ckgp.Params = bfv.DefaultParams[0]
		log.Lvl1("Starting ckgp")
		err = ckgp.Start()

		ckg_0 := (<-ckgp.ChannelPublicKey).Poly


		log.Lvl1("Public key is : " ,ckg_0)
		round.Record()
		if err != nil{
			log.Fatal("Could not start the tree : " , err )
		}
	return nil

}