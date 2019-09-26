package simulation


import (
"github.com/BurntSushi/toml"
"go.dedis.ch/onet/v3"
"go.dedis.ch/onet/v3/log"
)

/*
 * Defines the simulation for the service-template
 */

func init() {
	onet.SimulationRegister("KeyGenerationSim", NewKeyGenerationService)
}

// SimulationService only holds the BFTree simulation
type KeyGenerationService struct {
	onet.SimulationBFTree
}

// NewSimulationService returns the new simulation, where all fields are
// initialised using the config-file
func NewKeyGenerationService(config string) (onet.Simulation, error) {
	es := &KeyGenerationService{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (s *KeyGenerationService) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *KeyGenerationService) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

// Run is used on the destination machines and runs a number of
// rounds
func (s *KeyGenerationService) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)

	//c := onet.NewClient()
	//for round := 0; round < s.Rounds; round++ {
	//	log.Lvl1("Starting round", round)
	//	round := monitor.NewTimeMeasure("round")
	//	resp, err := c.Clock(config.Roster)
	//	log.ErrFatal(err)
	//	if resp.Time <= 0 {
	//		log.Fatal("0 time elapsed")
	//	}
	//	round.Record()
	//}
	return nil
}