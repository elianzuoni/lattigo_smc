package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

type KeySwitchingSim struct {
	onet.SimulationBFTree
	*bfv.Ciphertext

	lt           *utils.LocalTest
	ParamsIdx    int
	SwitchDegree uint64
	Params       *bfv.Parameters
}

var Cipher *bfv.Ciphertext

func init() {
	onet.SimulationRegister("CollectiveKeySwitching", NewSimulationKeySwitching)

}

func NewSimulationKeySwitching(config string) (onet.Simulation, error) {
	sim := &KeySwitchingSim{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	log.Lvl2("New Simulation key switching from init", sim.ParamsIdx)
	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

	log.Lvl4("New Key Switch instance : OK")

	return sim, nil
}

func (s *KeySwitchingSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//Setup following the config file.
	log.Lvl2("Setting up the simulation for key switching")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	log.Lvl2("here param idx ", s.ParamsIdx)
	s.lt, err = utils.GetLocalTestForRoster(sc.Roster, s.Params, storageDir)
	if err != nil {
		return nil, err
	}

	lt = s.lt

	//Generate the cipher text !
	ctxT, err := ring.NewContextWithParams(1<<s.Params.LogN, []uint64{s.Params.T})
	if err != nil {
		return nil, err
	}
	coeffs := ctxT.NewUniformPoly()
	enc := bfv.NewEncoder(s.Params)
	pt := bfv.NewPlaintext(s.Params)

	enc.EncodeUint(coeffs.Coeffs[0], pt)

	enc0 := bfv.NewEncryptorFromSk(s.Params, lt.IdealSecretKey0)

	s.Ciphertext = enc0.EncryptNew(pt)

	Cipher = s.Ciphertext

	return sc, nil
}

func (s *KeySwitchingSim) Node(config *onet.SimulationConfig) error {

	idx, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	//Inject the parameters.
	if _, err := config.Server.ProtocolRegister("CollectiveKeySwitchingSimul", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewKeySwitchingSimul(tni, s)
	}); err != nil {
		return errors.New("Error when registering Collective Key Switching instance " + err.Error())
	}
	s.lt = lt

	log.Lvl4("Node Setup OK")

	return s.SimulationBFTree.Node(config)
}

func NewKeySwitchingSimul(tni *onet.TreeNodeInstance, sim *KeySwitchingSim) (onet.ProtocolInstance, error) {
	log.Lvl2("NewKeySwitch simul with degree : ", sim.SwitchDegree)
	protocol, err := proto.NewCollectiveKeySwitching(tni)

	if err != nil {
		return nil, err
	}

	//cast
	colkeyswitch := protocol.(*proto.CollectiveKeySwitchingProtocol)
	sim.Ciphertext = Cipher
	err = colkeyswitch.Init(sim.Params, sim.lt.SecretKeyShares0[tni.ServerIdentity().ID], sim.lt.SecretKeyShares1[tni.ServerIdentity().ID], sim.Ciphertext)

	return colkeyswitch, nil
}

func (s *KeySwitchingSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	defer func() {
		err := lt.TearDown(true)
		if err != nil {
			log.Error(err)
		}
	}()
	timings := make([]time.Duration, s.Rounds)

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)
	for i := 0; i < s.Rounds; i++ {
		pi, err := config.Overlay.CreateProtocol("CollectiveKeySwitchingSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.Fatal("Couldn't create Protocol CollectiveKeySwitchingSimul:", err)
		}
		round := monitor.NewTimeMeasure("round")
		cksp := pi.(*proto.CollectiveKeySwitchingProtocol)

		log.Lvl4("Starting collective key switching protocol")
		now := time.Now()
		err = cksp.Start()
		defer cksp.Done()

		cksp.WaitDone()
		elapsed := time.Since(now)
		timings[i] = elapsed

		round.Record()

		log.Lvl1("Collective key switch done for  ", len(cksp.Roster().List), " nodes")
		log.Lvl1("Elapsed time : ", elapsed)

		//Check if correct...

		encoder := bfv.NewEncoder(s.Params)
		Decryptor1 := bfv.NewDecryptor(s.Params, lt.IdealSecretKey1)
		Decryptor0 := bfv.NewDecryptor(s.Params, lt.IdealSecretKey0)
		//expected

		expected := encoder.DecodeUint(Decryptor0.DecryptNew(s.Ciphertext))
		decoded := encoder.DecodeUint(Decryptor1.DecryptNew(cksp.CiphertextOut))
		log.Lvl2("Expected :", expected[0:25])
		log.Lvl2("Decoded : ", decoded[0:25])
		if !utils.Equalslice(expected, decoded) {
			log.Error("Decryption failed")
			return errors.New("decryption failed")
		}
		<-time.After(time.Second * 1)

	}

	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(s.Rounds)
	log.Lvl1("Average time : ", avg)

	return nil

}
