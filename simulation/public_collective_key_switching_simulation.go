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

type PublicKeySwitchingSim struct {
	onet.SimulationBFTree
	bfv.Ciphertext
	bfv.PublicKey
	bfv.SecretKey
}

var CipherPublic *bfv.Ciphertext
var PublicKey *bfv.PublicKey
var SecretKey *bfv.SecretKey

func init() {
	onet.SimulationRegister("CollectivePublicKeySwitching", NewSimulationPublicKeySwitching)
	//Setting up params.
	params := (bfv.DefaultParams[0])
	CipherPublic = bfv.NewCiphertextRandom(params, 1)
	keygen := bfv.NewKeyGenerator(params)
	SecretKey = keygen.NewSecretKey()
	PublicKey = keygen.NewPublicKey(SecretKey)
}

func NewSimulationPublicKeySwitching(config string) (onet.Simulation, error) {
	sim := &PublicKeySwitchingSim{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}
	//Give the params.
	sim.Ciphertext = *CipherPublic
	sim.PublicKey = *PublicKey
	sim.SecretKey = *SecretKey
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

	log.Lvl4("Node setup ok")

	return s.SimulationBFTree.Node(config)
}

func (s *PublicKeySwitchingSim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)

	round := monitor.NewTimeMeasure("round")

	//local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	//defer local.CloseAll()

	log.Lvl1("Starting Public collective key switching simul")

	pi, err := config.Overlay.CreateProtocol("CollectivePublicKeySwitchingSimul", config.Tree, onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create new node:", err)
		return err
	}

	pcksp := pi.(*proto.CollectivePublicKeySwitchingProtocol)
	err = pcksp.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	<-time.After(5 * time.Second)

	log.Lvl1("Public Collective key switching done. Now comparing the cipher texts. ")
	i := 0
	params := bfv.DefaultParams[0]
	tmp0 := params.NewPolyQ()
	ctx, err := ring.NewContextWithParams(1<<params.LogN, params.Moduli.Qi)
	if err != nil {
		return err
	}
	for i < size {
		si := config.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(params, "sk0"+si)
		if err != nil {
			fmt.Print("error : ", err)
		}

		ctx.Add(tmp0, sk0.Get(), tmp0)

		i++
	}

	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)

	DecryptorOutput := bfv.NewDecryptor(params, SecretKey)

	DecryptorInput := bfv.NewDecryptor(params, SkInput)

	encoder := bfv.NewEncoder(params)

	//Get expected result.
	decrypted := DecryptorInput.DecryptNew(CipherPublic)
	expected := encoder.DecodeUint(decrypted)

	i = 0
	for i < size {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfv.NewPlaintext(params)
		DecryptorOutput.Decrypt(&newCipher, res)

		log.Lvl1("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")
			pcksp.Done()
			return errors.New("Plaintext do not match")

		}
		i++
	}
	pcksp.Done()
	log.Lvl1("Got all matches on ciphers.")
	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Success")
	round.Record()

	log.Lvl4("finished")
	return nil

}

func NewPublicKeySwitchingSimul(tni *onet.TreeNodeInstance, sim *PublicKeySwitchingSim) (onet.ProtocolInstance, error) {
	//This part allows to injec the data to the node ~ we don't need the messy channels.
	log.Lvl1("New pubkey switch simul")
	protocol, err := proto.NewCollectivePublicKeySwitching(tni)

	if err != nil {
		return nil, err
	}

	//cast
	keygen := protocol.(*proto.CollectivePublicKeySwitchingProtocol)
	keygen.Params = *bfv.DefaultParams[0]
	keygen.Sk.SecretKey = "sk0"
	keygen.Ciphertext = sim.Ciphertext
	keygen.PublicKey = sim.PublicKey
	return keygen, nil

}
