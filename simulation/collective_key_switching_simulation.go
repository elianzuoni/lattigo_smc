package simulation

import (
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
"github.com/ldsec/lattigo/bfv"
"go.dedis.ch/onet/v3"
"go.dedis.ch/onet/v3/log"
"go.dedis.ch/onet/v3/simul/monitor"
proto "protocols/protocols"
	"protocols/utils"
	"time"
)

type KeySwitchingSim struct {
	onet.SimulationBFTree
}

func init(){
	onet.SimulationRegister("CollectiveKeySwitching",NewSimulationKeySwitching)
}

func NewSimulationKeySwitching(config string)(onet.Simulation, error){
	sim := &KeySwitchingSim{}

	_,err := toml.Decode(config,sim)
	if err != nil{
		return nil,err
	}

	return sim,nil
}

func (s* KeySwitchingSim) Setup(dir string,hosts []string)(*onet.SimulationConfig,error){
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

func (s* KeySwitchingSim) Node(config *onet.SimulationConfig)error{
	idx , _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	log.Lvl4("Node setup")

	return s.SimulationBFTree.Node(config)
}

func (s *KeySwitchingSim)Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : " , size, " rounds : " , s.Rounds)





	round := monitor.NewTimeMeasure("round")




	bfvCtx,err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil{
		log.Print("Could not load bfv ctx ",err)
		return err
	}

	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	tmp1 := bfvCtx.ContextQ().NewPoly()
	for i < size{
		si := config.Tree.Roster.List[i].String()
		sk0 ,err := utils.GetSecretKey(bfvCtx,"sk0"+si)
		if err!=nil{
			fmt.Print("error : " , err)
		}
		sk1 , err := utils.GetSecretKey(bfvCtx,"sk1"+si)
		if err != nil{
			fmt.Print("err : " , err )
		}

		bfvCtx.ContextQ().Add(tmp0,sk0.Get(),tmp0)
		bfvCtx.ContextQ().Add(tmp1,sk1.Get(),tmp1)

		i++
	}
	SkInput := new(bfv.SecretKey)
	SkOutput := new(bfv.SecretKey)
	SkInput.Set(tmp0)
	SkOutput.Set(tmp1)


	keygen := bfvCtx.NewKeyGenerator()
	PkInput  := keygen.NewPublicKey(SkInput)


	ski,_ := SkInput.MarshalBinary()
	log.Lvl4("At start ski  : " , ski[0:25])
	sko,_ := SkOutput.MarshalBinary()
	log.Lvl4("At start  sko  : " , sko[0:25])

	PlainText := bfvCtx.NewPlaintext()
	encoder,err := bfvCtx.NewBatchEncoder()
	log.Print(PlainText.Degree())
	expected := bfvCtx.NewRandomPlaintextCoeffs()

	err = encoder.EncodeUint(expected,PlainText)
	if err != nil{
		log.Print("Could not encode plaintext : " , err)
		return err
	}

	Encryptor ,err := bfvCtx.NewEncryptorFromPk(PkInput)


	CipherText,err := Encryptor.EncryptNew(PlainText)


	//TODO what is the service ID ?
	pi,err := config.Overlay.StartProtocol("CollectiveKeySwitching",config.Tree,onet.NilServiceID)
	if err != nil {
		log.Fatal("Couldn't create new node:", err)
	}

	cksp := pi.(*proto.CollectiveKeySwitchingProtocol)
	cksp.Params = proto.SwitchingParameters{
		Params:       bfv.DefaultParams[0],
		SkInputHash:  "sk0",
		SkOutputHash: "sk1",
		Ciphertext:   *CipherText,
	}

	log.Lvl4("Starting collective key switching protocol")
	err = cksp.Start()

	log.Lvl4("Collective key switch done for  " ,len(cksp.Roster().List) , " nodes.\n\tNow comparing verifying ciphers.")
	<- time.After(5*time.Second)


	//check if all ciphers are ok
	//here for the sake of the test the cipher text is written to a file.
	if proto.Test(){
		defer cksp.Done()
		Decryptor,err := bfvCtx.NewDecryptor(SkOutput)
		if err != nil{
			return err
		}

		i = 0
		for i < size{
			newCipher := (<- cksp.ChannelCiphertext).Ciphertext
			d,_ := newCipher.MarshalBinary()
			log.Lvl4("Got cipher : " , d[0:25])
			res := bfvCtx.NewPlaintext()
			Decryptor.Decrypt(&newCipher , res)


			log.Lvl1("Comparing a cipher..")
			decoded := encoder.DecodeUint(res)
			ok := utils.Equalslice(decoded,expected)

			if !ok{
				cksp.Done()
				return errors.New("Plaintext do not match")

			}
			i ++
		}
		cksp.Done()
		log.Lvl1("Got all matches on ciphers.")
	}



	round.Record()
	if err != nil{
		log.Fatal("Could not start the tree : " , err )
	}


	log.Lvl4("finished")
	return nil


}
