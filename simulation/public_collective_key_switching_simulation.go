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

type PublicKeySwitchingSim struct {
	onet.SimulationBFTree
	*bfv.Ciphertext
	*bfv.PublicKey
	*bfv.SecretKey

	lt           *utils.LocalTest
	ParamsIdx    int
	SwitchDegree uint64
	Params       *bfv.Parameters
}

var PublicKey *bfv.PublicKey

func init() {
	onet.SimulationRegister("CollectivePublicKeySwitching", NewSimulationPublicKeySwitching)

}

func NewSimulationPublicKeySwitching(config string) (onet.Simulation, error) {
	sim := &PublicKeySwitchingSim{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}
	//Give the params.
	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

	return sim, nil
}

func (s *PublicKeySwitchingSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//setup following the config file.
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
	lt = s.lt
	//Generate the cipher text. & public key
	ctxT, err := ring.NewContextWithParams(1<<s.Params.LogN, []uint64{s.Params.T})
	if err != nil {
		return nil, err
	}
	coeffs := ctxT.NewUniformPoly()
	enc := bfv.NewEncoder(s.Params)
	pt := bfv.NewPlaintext(s.Params)

	enc.EncodeUint(coeffs.Coeffs[0], pt)
	pt = bfv.NewPlaintext(s.Params)
	pk := bfv.NewKeyGenerator(s.Params).GenPublicKey(s.lt.IdealSecretKey1)
	enc1 := bfv.NewEncryptorFromPk(s.Params, pk)

	s.Ciphertext = enc1.EncryptNew(pt)
	Cipher = s.Ciphertext
	PublicKey = pk

	return sc, nil
}

func (s *PublicKeySwitchingSim) Node(config *onet.SimulationConfig) error {
	idx, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	//Inject parameters
	log.Lvl4("Node setup")
	if _, err := config.Server.ProtocolRegister("CollectivePublicKeySwitchingSimul", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewPublicKeySwitchingSimul(tni, s)
	}); err != nil {
		return errors.New("Error when registering Collective Key Switching instance " + err.Error())
	}

	s.lt = lt

	log.Lvl4("Node setup ok")

	return s.SimulationBFTree.Node(config)
}

func NewPublicKeySwitchingSimul(tni *onet.TreeNodeInstance, sim *PublicKeySwitchingSim) (onet.ProtocolInstance, error) {
	//This part allows to injec the data to the node ~ we don't need the messy channels.
	log.Lvl3("New pubkey switch simul")
	protocol, err := proto.NewCollectivePublicKeySwitching(tni)

	if err != nil {
		return nil, err
	}

	//cast
	publickeyswitch := protocol.(*proto.CollectivePublicKeySwitchingProtocol)
	sim.Ciphertext = Cipher
	sim.PublicKey = PublicKey

	err = publickeyswitch.Init(*sim.Params, *sim.PublicKey, *lt.SecretKeyShares0[tni.ServerIdentity().ID], sim.Ciphertext)
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
	//local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	//defer local.CloseAll()

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
		pcksp.Wait()
		elapsed := time.Since(now)
		timings[i] = elapsed
		round.Record()

		log.Lvl1("Public Collective key switching done.")
		log.Lvl1("Elapsed time :", elapsed)

		//Check if correct.
		encoder := bfv.NewEncoder(s.Params)
		DecryptorOutput := bfv.NewDecryptor(s.Params, lt.IdealSecretKey1)
		DecryptorInput := bfv.NewDecryptor(s.Params, lt.IdealSecretKey0)
		plaintext := DecryptorInput.DecryptNew(Cipher)
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
