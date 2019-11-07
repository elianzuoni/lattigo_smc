//This file holds the Relinearization key protocol
//Contains all method that are implemented in order to implement a protocol from onet.
package main

import (
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	proto "lattigo-smc/protocols"
	"lattigo-smc/utils"

	"time"
)

type RelinearizationKeySimulation struct {
	onet.SimulationBFTree
}


const BitDecomp = 64

func init() {
	onet.SimulationRegister("RelinearizationKeyGeneration", NewRelinearizationKeyGeneration)
}

func NewRelinearizationKeyGeneration(config string) (onet.Simulation, error) {
	sim := &RelinearizationKeySimulation{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

func (s *RelinearizationKeySimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//setup following the config file.
	log.Lvl4("Setting up the simulations")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *RelinearizationKeySimulation) Node(config *onet.SimulationConfig) error {
	//todo inject parameters here !
	idx, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	log.Lvl4("Node setup")

	return s.SimulationBFTree.Node(config)
}

func (s *RelinearizationKeySimulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	SKHash := "sk0"

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)

	round := monitor.NewTimeMeasure("round")



	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	if err != nil {
		log.Print("Could not load bfv ctx ", err)
		return err
	}
	i := 0
	tmp0 := bfvCtx.ContextQ().NewPoly()
	for i < size {
		si := config.Tree.Roster.List[i].String()
		sk0, err := utils.GetSecretKey(bfvCtx, SKHash+si)
		if err != nil {
			log.Error("error : ", err)
			return err
		}

		bfvCtx.ContextQ().Add(tmp0, sk0.Get(), tmp0)

		i++
	}


	Sk := new(bfv.SecretKey)
	Sk.Set(tmp0)
	Pk := bfvCtx.NewKeyGenerator().NewPublicKey(Sk)
	encryptor_pk,_ := bfvCtx.NewEncryptorFromPk(Pk)
	//encrypt some cipher text...

	PlainText := bfvCtx.NewPlaintext()
	encoder, err := bfvCtx.NewBatchEncoder()
	if err != nil{
		log.Error(err)
		return err
	}
	expected := bfvCtx.ContextT().NewUniformPoly()

	err = encoder.EncodeUint(expected.Coeffs[0], PlainText)
	if err != nil {
		log.Print("Could not encode plaintext : ", err)
		return err
	}



	CipherText, err := encryptor_pk.EncryptNew(PlainText)

	if err != nil {
		log.Print("error in encryption : ", err)
		return err
	}
	//multiply it !
	evaluator := bfvCtx.NewEvaluator()

	MulCiphertext ,_ := evaluator.MulNew(CipherText,CipherText)
	//we want to relinearize MulCiphertexts
	ExpectedCoeffs := bfvCtx.ContextT().NewPoly()
	bfvCtx.ContextT().MulCoeffs(expected, expected, ExpectedCoeffs)
	//in the end of relin we should have RelinCipher === ExpectedCoeffs.
	contextQ := bfvCtx.ContextQ()
	bitLog := uint64((60 + (60 % BitDecomp)) / BitDecomp)

	//Parameters ***************************
	//Computation for the crp (a)
	crpGenerators := make([]*dbfv.CRPGenerator, size)
	for i := 0; i < size; i++ {
		crpGenerators[i], err = dbfv.NewCRPGenerator(nil, contextQ)
		if err != nil {
			log.Error(err)
			return err
		}
		crpGenerators[i].Seed([]byte{})
	}
	crp := make([][]*ring.Poly, len(contextQ.Modulus))
	for j := 0; j < len(contextQ.Modulus); j++ {
		crp[j] = make([]*ring.Poly, bitLog)
		for u := uint64(0); u < bitLog; u++ {
			crp[j][u] = crpGenerators[0].Clock()
		}
	}


	//The parameters are sk,crp,bfvParams
	pi, err := config.Overlay.CreateProtocol("RelinearizationKeyProtocol", config.Tree,onet.NilServiceID)
	if err != nil {
		log.Error(err)
		return err
	}


	RelinProtocol := pi.(*proto.RelinearizationKeyProtocol)
	RelinProtocol.Params = bfv.DefaultParams[0]
	RelinProtocol.Sk = proto.SK{"sk0"}
	RelinProtocol.Crp = proto.CRP{A:crp}
	<- time.After(2*time.Second)

	//Now we can start the protocol
	err = RelinProtocol.Start()
	defer RelinProtocol.Done()
	if err != nil{
		log.Error("Could not start relinearization protocol : " , err )
		return err
	}

	<- time.After(3*time.Second)
	log.Lvl1("Collecting the relinearization keys")
	array := make([]bfv.EvaluationKey, size)
	//check if the keys are the same for all parties
	for i := 0 ; i < size; i++{
		relkey := (<-RelinProtocol.ChannelEvalKey).EvaluationKey
		data, _ := relkey.MarshalBinary()
		log.Lvl3("Key starting with : " , data[0:25])
		log.Lvl3("Got one eval key...")
		array[i] = relkey
	}

	err = utils.CompareEvalKeys(array)
	if err != nil{
		log.Error("Different relinearization keys : ", err )

		return err
	}
	log.Lvl1("Check : all peers have the same key ")
	rlk := array[0]
	ResCipher , err := evaluator.RelinearizeNew(MulCiphertext,&rlk)
	if err != nil{
		log.Error("Could not relinearize the cipher text : ", err)
		return err
	}

	//decrypt the cipher
	decryptor,_ := bfvCtx.NewDecryptor(Sk)
	resDecrypted := decryptor.DecryptNew(ResCipher)
	resDecoded := encoder.DecodeUint(resDecrypted)
	if ! utils.Equalslice(ExpectedCoeffs.Coeffs[0],resDecoded){
		log.Error("Decrypted relinearized cipher is not equal to expected plaintext")
		return err
	}
	log.Lvl1("Relinearization done.")



	round.Record()


	log.Lvl1("finished")
	return nil

}
