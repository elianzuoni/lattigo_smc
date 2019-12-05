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
	proto "lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

type KeySwitchingSim struct {
	onet.SimulationBFTree
	bfv.Ciphertext
}

var Cipher bfv.Ciphertext

func init() {
	onet.SimulationRegister("CollectiveKeySwitching", NewSimulationKeySwitching)
	//todo find cleaner way
	params := bfv.DefaultParams[0]
	Cipher = *bfv.NewCiphertextRandom(params, 1)
}

func NewSimulationKeySwitching(config string) (onet.Simulation, error) {
	sim := &KeySwitchingSim{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	sim.Ciphertext = Cipher

	log.Lvl1("New Key Switch instance : OK")

	return sim, nil
}

func (s *KeySwitchingSim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//setup following the config file.
	log.Lvl1("Setting up the simulation for key switching")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)

	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *KeySwitchingSim) Node(config *onet.SimulationConfig) error {
	log.Lvl1("Node setup")

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
	log.Lvl1("Node setup OK")

	return s.SimulationBFTree.Node(config)
}

func NewKeySwitchingSimul(tni *onet.TreeNodeInstance, sim *KeySwitchingSim) (onet.ProtocolInstance, error) {
	log.Lvl1("NewKeySwitch simul")
	protocol, err := proto.NewCollectiveKeySwitching(tni)

	if err != nil {
		return nil, err
	}

	//cast
	colkeyswitch := protocol.(*proto.CollectiveKeySwitchingProtocol)
	colkeyswitch.Params = proto.SwitchingParameters{
		Params:       *bfv.DefaultParams[0],
		SkInputHash:  "sk0",
		SkOutputHash: "sk1",
		Ciphertext:   sim.Ciphertext, //todo How to inject the cipher text...
	}

	return colkeyswitch, nil
}

func (s *KeySwitchingSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)

	round := monitor.NewTimeMeasure("round")

	//TODO what is the service ID ?
	pi, err := config.Overlay.CreateProtocol("CollectiveKeySwitchingSimul", config.Tree, onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create Protocol CollectiveKeySwitchingSimul:", err)
	}

	cksp := pi.(*proto.CollectiveKeySwitchingProtocol)

	log.Lvl4("Starting collective key switching protocol")
	err = cksp.Start()

	log.Lvl4("Collective key switch done for  ", len(cksp.Roster().List), " nodes.\n\tNow comparing verifying ciphers.")
	<-time.After(5 * time.Second)

	//Now we can setup our keys..
	params := bfv.DefaultParams[0]

	i := 0
	tmp0 := params.NewPolyQ()
	tmp1 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		return err
	}
	for i < size {
		si := config.Tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(params, "sk0"+si)
		if err != nil {
			fmt.Print("error : ", err)
		}
		sk1, err := utils.GetSecretKey(params, "sk1"+si)
		if err != nil {
			fmt.Print("err : ", err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)
		ctx.Add(tmp1, sk1.Get(), tmp1)

		i++
	}
	SkInput := new(bfv.SecretKey)
	SkOutput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	SkOutput.Set(tmp1)

	encoder := bfv.NewEncoder(params)

	DecryptorInput := bfv.NewDecryptor(params, SkInput)

	//expected
	ReferencePlaintext := DecryptorInput.DecryptNew(&s.Ciphertext)
	expected := encoder.DecodeUint(ReferencePlaintext)

	DecryptorOutput := bfv.NewDecryptor(params, SkOutput)
	log.Lvl1("test is downloading the ciphertext..")
	//check if all ciphers are ok
	defer cksp.Done()

	i = 0
	for i < size {
		newCipher := (<-cksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(params)
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl1("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			cksp.Done()
			return errors.New("plaintexts do not match")

		}
		i++
	}
	cksp.Done()
	log.Lvl1("Got all matches on ciphers.")

	round.Record()

	log.Lvl4("finished")
	return nil

}
