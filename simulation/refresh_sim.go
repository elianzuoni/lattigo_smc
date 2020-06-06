package main

import (
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

type RefreshSimulation struct {
	*onet.SimulationBFTree

	lt        *utils.LocalTest
	ParamsIdx int

	Params *bfv.Parameters
	sk     *bfv.SecretKey
	crs    *ring.Poly
	ct     *bfv.Ciphertext
}

func init() {
	onet.SimulationRegister("CollectiveRefresh", NewSimulationRefresh)
}

func NewSimulationRefresh(config string) (onet.Simulation, error) {
	sim := &RefreshSimulation{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

	return sim, nil
}

func (s *RefreshSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	log.Lvl2("Setting up a simulation for refresh")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	log.Lvl2("Gettign local test. ")

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

func (s *RefreshSimulation) Node(config *onet.SimulationConfig) error {
	if _, err := config.Server.ProtocolRegister("CollectiveRefreshSimul", func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
		return SimNewRefreshProto(tni, s)
	}); err != nil {
		return errors.New("Error when registereing collecting refresh " + err.Error())
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

	// Pre-load the CRS
	s.crs = s.lt.CRS

	// Pre-load the Ciphertext
	s.ct = s.lt.Ciphertext

	log.Lvl3("Node Setup OK")
	return s.SimulationBFTree.Node(config)
}

func SimNewRefreshProto(tni *onet.TreeNodeInstance, sim *RefreshSimulation) (onet.ProtocolInstance, error) {
	protocol, err := protocols.NewCollectiveRefresh(tni)
	if err != nil {
		return nil, err
	}

	refresh := protocol.(*protocols.RefreshProtocol)
	err = refresh.Init(*sim.Params, sim.sk, *sim.ct, *sim.crs)
	return refresh, err
}

func (s *RefreshSimulation) Run(config *onet.SimulationConfig) error {
	defer func() {
		err := s.lt.TearDown(true)
		if err != nil {
			log.Error(err)
		}
	}()
	timings := make([]time.Duration, s.Rounds)
	for i := 0; i < s.Rounds; i++ {

		pi, err := config.Overlay.CreateProtocol("CollectiveRefreshSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.Fatal("Could not create protocol for refresh", err)
		}

		round := monitor.NewTimeMeasure("round")
		rp := pi.(*protocols.RefreshProtocol)
		now := time.Now()
		err = rp.Start()
		defer rp.Done()
		rp.WaitDone()
		elapsed := time.Since(now)
		timings[i] = elapsed
		round.Record()
		log.Lvl1("Collective Refresh done for  ", len(rp.Roster().List), " nodes")
		log.Lvl1("Elapsed time : ", elapsed)

		//check for correcteness.
		encoder := bfv.NewEncoder(s.Params)
		DecryptorInput := bfv.NewDecryptor(s.Params, s.lt.IdealSecretKey0)
		//Expected result
		expected := encoder.DecodeUint(DecryptorInput.DecryptNew(s.ct))
		decoded := encoder.DecodeUint(DecryptorInput.DecryptNew(&rp.FinalCiphertext))
		if !utils.Equalslice(expected, decoded) {
			log.Error("Decryption failed")
			return errors.New("decryption failed")
		}
		<-time.After(500 * time.Millisecond)
	}

	log.Lvl1("Success!")
	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(s.Rounds)
	log.Lvl1("Average time : ", avg)
	return nil
}
