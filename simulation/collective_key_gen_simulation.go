package simulation

import (
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "protocols/protocols"
	"protocols/utils"
	"time"
)

type KeyGenerationSim struct {
	onet.SimulationBFTree
}

func init(){
	onet.SimulationRegister("CollectiveKeyGeneration",NewSimulationKeyGen)
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
	log.Lvl4("Setting up the simulations")
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

	log.Lvl4("Node setup")

	return s.SimulationBFTree.Node(config)
}

func (s *KeyGenerationSim)Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : " , size, " rounds : " , s.Rounds)

	round := monitor.NewTimeMeasure("round")

	//TODO what is the service ID ?
	pi,err := config.Overlay.StartProtocol("CollectiveKeyGeneration",config.Tree,onet.NilServiceID)
		if err != nil {
			log.Fatal("Couldn't create new node:", err)
		}

		ckgp := pi.(*proto.CollectiveKeyGenerationProtocol)
		ckgp.Params = bfv.DefaultParams[0]
		log.Lvl4("Starting ckgp")
		err = ckgp.Start()

	log.Lvl1("Collective Key Generated for " ,len(ckgp.Roster().List) , " nodes.\n\tNow comparing all polynomials.")
	<- time.After(2*time.Second)
	//check if we have all the same polys ckg_0
	CheckKeys(ckgp,err)
	round.Record()
		if err != nil{
			log.Fatal("Could not start the tree : " , err )
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
	for _, k1 := range (keys) {
		for _, k2 := range (keys) {
			err := utils.CompareKeys(k1, k2)
			if err != nil {
				log.Error("Error in polynomial comparison : ", err)
			}
		}
	}
}
