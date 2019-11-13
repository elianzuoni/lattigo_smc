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

type KeySwitchingSim struct {
	onet.SimulationBFTree
	bfv.Ciphertext
}

var Cipher bfv.Ciphertext

func init() {
	onet.SimulationRegister("CollectiveKeySwitching", NewSimulationKeySwitching)
	//todo find cleaner way
	bfvCtx, _ := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	Cipher = *bfvCtx.NewRandomCiphertext(1)

}

func NewSimulationKeySwitching(config string) (onet.Simulation, error) {
	sim := &KeySwitchingSim{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	sim.Ciphertext = Cipher

	log.Lvl1("OK")

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
		Params:       bfv.DefaultParams[0],
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
	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		return err
	}
	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	tmp1 := bfvCtx.ContextQ().NewPoly()
	for i < size {
		si := config.Tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(bfvCtx, "sk0"+si)
		if err != nil {
			fmt.Print("error : ", err)
		}
		sk1, err := utils.GetSecretKey(bfvCtx, "sk1"+si)
		if err != nil {
			fmt.Print("err : ", err)
		}

		bfvCtx.ContextQ().Add(tmp0, sk0.Get(), tmp0)
		bfvCtx.ContextQ().Add(tmp1, sk1.Get(), tmp1)

		i++
	}
	SkInput := new(bfv.SecretKey)
	SkOutput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	SkOutput.Set(tmp1)

	encoder, err := bfvCtx.NewBatchEncoder()
	if err != nil {
		log.Error("Could not start encoder : ", err)
		return err
	}

	DecryptorInput, err := bfvCtx.NewDecryptor(SkInput)
	if err != nil {
		log.Error(err)
		return err
	}

	//expected
	ReferencePlaintext := DecryptorInput.DecryptNew(&s.Ciphertext)
	d, _ := s.Ciphertext.MarshalBinary()
	log.Lvl1("REFERENCE CIPHER ", d[0:25])
	expected := encoder.DecodeUint(ReferencePlaintext)

	DecryptorOutput, err := bfvCtx.NewDecryptor(SkOutput)
	if err != nil {
		log.Error(err)
		return err
	}
	//check if all ciphers are ok
	defer cksp.Done()

	i = 0
	for i < size {
		newCipher := (<-cksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfvCtx.NewPlaintext()
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl1("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			cksp.Done()
			return errors.New("Plaintext do not match")

		}
		i++
	}
	cksp.Done()
	log.Lvl1("Got all matches on ciphers.")

	round.Record()
	if err != nil {
		log.Fatal("Could not start the tree : ", err)
	}

	log.Lvl4("finished")
	return nil

}
