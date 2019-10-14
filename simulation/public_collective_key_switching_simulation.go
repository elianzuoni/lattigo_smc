package simulation

import (
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "protocols/protocols"
	"protocols/utils"
	"time"
)

type PublicKeySwitchingSim struct {
	onet.SimulationBFTree
}

func init(){
	onet.SimulationRegister("PublicCollectiveKeySwitching",NewSimulationPublicKeySwitching)
}

func NewSimulationPublicKeySwitching(config string)(onet.Simulation, error){
	sim := &PublicKeySwitchingSim{}

	_,err := toml.Decode(config,sim)
	if err != nil{
		return nil,err
	}

	return sim,nil
}

func (s* PublicKeySwitchingSim) Setup(dir string,hosts []string)(*onet.SimulationConfig,error){
	//setup following the config file.
	log.Lvl4("Setting up the simulation for key switching")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc,hosts,2000)
	err := s.CreateTree(sc)
	if err != nil{
		return nil, err
	}
	return sc,nil
}

func (s* PublicKeySwitchingSim) Node(config *onet.SimulationConfig)error{
	idx , _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	log.Lvl4("Node setup")

	return s.SimulationBFTree.Node(config)
}



func (s *PublicKeySwitchingSim)Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : " , size, " rounds : " , s.Rounds)

	round := monitor.NewTimeMeasure("round")




	log.SetDebugVisible(1)
	log.Lvl1("Started to test collective key switching locally with nodes amount : ", size)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(size, true)

	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		return err
	}
	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	for i < size {
		si := tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(bfvCtx, "sk0"+si)
		if err != nil {
			fmt.Print("error : ", err)
		}

		bfvCtx.ContextQ().Add(tmp0, sk0.Get(), tmp0)

		i++
	}
	SkInput := new(bfv.SecretKey)
	SkInput.Set(tmp0)

	//keygen := bfvCtx.NewKeyGenerator()
	//PkInput  := keygen.NewPublicKey(SkInput)

	ski, err := SkInput.MarshalBinary()
	log.Lvl4("At start ski  : ", ski[0:25])

	if err != nil {
		log.Print("Could not load secret keys : ", err)
		return err
	}

	PlainText := bfvCtx.NewPlaintext()
	encoder, err := bfvCtx.NewBatchEncoder()
	expected := bfvCtx.NewRandomPlaintextCoeffs()

	err = encoder.EncodeUint(expected, PlainText)
	if err != nil {
		log.Print("Could not encode plaintext : ", err)
		return err
	}

	Encryptor, err := bfvCtx.NewEncryptorFromSk(SkInput)

	CipherText, err := Encryptor.EncryptNew(PlainText)

	if err != nil {
		log.Print("error in encryption : ", err)
		return err
	}
	SkOutput := bfvCtx.NewKeyGenerator().NewSecretKey()
	publickey := bfvCtx.NewKeyGenerator().NewPublicKey(SkOutput)


	pi,err := config.Overlay.StartProtocol("PublicCollectiveKeySwitching",config.Tree,onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create new node:", err)
		return err
	}


	<-time.After(5*time.Second)
	pcksp := pi.(*proto.PublicCollectiveKeySwitchingProtocol)
	pcksp.Params = bfv.DefaultParams[0]
	pcksp.Sk = "sk0"
	pcksp.PublicKey = *publickey
	pcksp.Ciphertext = *CipherText

	//cksp.Params = bfv.DefaultParams[0]
	log.Lvl4("Starting cksp")

	//err = pcksp.Start()
	//if err != nil {
	//	return err
	//}


	<-time.After(2 * time.Second)


	log.Lvl1("Public Collective key switching done. Now comparing the cipher texts. ")

	Decryptor, err := bfvCtx.NewDecryptor(SkOutput)
	i = 0
	for i < size {
		newCipher := (<-pcksp.ChannelCiphertext).Ciphertext
		d, _ := newCipher.MarshalBinary()
		log.Lvl4("Got cipher : ", d[0:25])
		res := bfvCtx.NewPlaintext()
		Decryptor.Decrypt(&newCipher, res)

		log.Lvl1("Comparing a cipher..")
		decoded := encoder.DecodeUint(res)
		ok := utils.Equalslice(decoded, expected)

		if !ok {
			log.Print("Plaintext do not match ")

			pcksp.Done()
			return errors.New("Non matching plain text ")

		}
		i++
	}

	pcksp.Done()
	log.Lvl1("Got all matches on ciphers.")
	//check if the resulting cipher text decrypted with SkOutput works

	log.Lvl1("Success")



	round.Record()
	if err != nil{
		log.Fatal("Could not start the tree : " , err )
	}


	log.Lvl4("finished")
	return nil


}


