package main

import (
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

type PublicKeySwitchingSim struct {
	onet.SimulationBFTree

	lt        *utils.LocalTest
	ParamsIdx int

	Params *bfv.Parameters
	sk     *bfv.SecretKey
	ct     *bfv.Ciphertext
	pk     *bfv.PublicKey
}

func init() {
	onet.SimulationRegister("CollectivePublicKeySwitching", NewSimulationPublicKeySwitching)
}

func NewSimulationPublicKeySwitching(config string) (onet.Simulation, error) {
	sim := &PublicKeySwitchingSim{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

	return sim, nil
}

func (s *PublicKeySwitchingSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//Setup following the config file.
	log.Lvl4("Setting up the simulation for key switching")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	s.lt, err = utils.GetLocalTestForRoster(sc.Roster, s.Params, storageDir)
	if err != nil {
		return nil, err
	}

	// Write the local test to file
	err = s.lt.WriteToFile(dir + "/local_test")
	if err != nil {
		return nil, err
	}

	return sc, nil
}

func (s *PublicKeySwitchingSim) Node(config *onet.SimulationConfig) error {
	idx, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	//Inject parameters
	log.Lvl4("Node Setup")
	if _, err := config.Server.ProtocolRegister("CollectivePublicKeySwitchingSimul", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return SimNewPCKSProto(tni, s)
	}); err != nil {
		return errors.New("Error when registering Collective Key Switching instance " + err.Error())
	}

	// Read the local test from file
	s.lt = &utils.LocalTest{StorageDirectory: storageDir}
	err := s.lt.ReadFromFile("local_test")
	if err != nil {
		return err
	}

	// Pre-load the secret key
	var found bool
	s.sk, found = s.lt.SecretKeyShares0[config.Server.ServerIdentity.ID]
	if !found {
		return fmt.Errorf("secret key share for %s not found", config.Server.ServerIdentity.ID.String())
	}

	// Pre-load the Ciphertext
	s.ct = s.lt.Ciphertext

	// Compute the public key
	s.pk = bfv.NewKeyGenerator(s.Params).GenPublicKey(s.lt.IdealSecretKey1)

	log.Lvl4("Node Setup ok")

	return s.SimulationBFTree.Node(config)
}

func SimNewPCKSProto(tni *onet.TreeNodeInstance, sim *PublicKeySwitchingSim) (onet.ProtocolInstance, error) {
	//This part allows to injec the data to the node ~ we don't need the messy channels.
	log.Lvl3("New pubkey switch simul")
	protocol, err := proto.NewCollectivePublicKeySwitching(tni)

	if err != nil {
		return nil, err
	}

	//cast
	publickeyswitch := protocol.(*proto.CollectivePublicKeySwitchingProtocol)
	err = publickeyswitch.Init(*sim.Params, *sim.pk, *sim.sk, sim.ct)
	return publickeyswitch, nil

}

func (s *PublicKeySwitchingSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	defer func() {
		err := s.lt.TearDown(true)
		if err != nil {
			log.Error(err)
		}
	}()

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)
	timings := make([]time.Duration, s.Rounds)

	log.Lvl3("Starting Public collective key switching simul")
	for i := 0; i < s.Rounds; i++ {

		pi, err := config.Overlay.CreateProtocol("CollectivePublicKeySwitchingSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.Fatal("Couldn't create new node:", err)
			return err
		}

		pcksp := pi.(*proto.CollectivePublicKeySwitchingProtocol)
		round := monitor.NewTimeMeasure("round")
		now := time.Now()
		err = pcksp.Start()
		if err != nil {
			log.Error(err)
			return err
		}
		pcksp.WaitDone()
		elapsed := time.Since(now)
		timings[i] = elapsed
		round.Record()

		log.Lvl1("Public Collective key switching done.")
		log.Lvl1("Elapsed time :", elapsed)

		//Check if correct.
		encoder := bfv.NewEncoder(s.Params)
		DecryptorOutput := bfv.NewDecryptor(s.Params, s.lt.IdealSecretKey1)
		DecryptorInput := bfv.NewDecryptor(s.Params, s.lt.IdealSecretKey0)
		plaintext := DecryptorInput.DecryptNew(s.ct)
		expected := encoder.DecodeUint(plaintext)
		decoded := encoder.DecodeUint(DecryptorOutput.DecryptNew(&pcksp.CiphertextOut))

		if !utils.Equalslice(expected, decoded) {
			log.Error("Decryption failed")
		}
		<-time.After(time.Second)
	}
	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(s.Rounds)
	log.Lvl1("Average time : ", avg)
	return nil

}
