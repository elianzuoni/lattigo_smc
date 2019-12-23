//This file holds the Relinearization key protocol
//Contains all method that are implemented in order to implement a protocol from onet.
package main

import (
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

type RelinearizationKeySimulation struct {
	onet.SimulationBFTree
	proto.CRP
}

const BitDecomp = 64

var CRP proto.CRP

const SkHash = "sk0"

func init() {
	onet.SimulationRegister("RelinearizationKeyGeneration", NewRelinearizationKeyGeneration)

}

func NewRelinearizationKeyGeneration(config string) (onet.Simulation, error) {
	sim := &RelinearizationKeySimulation{}

	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	sim.CRP = CRP

	return sim, nil
}

func (s *RelinearizationKeySimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	//setup following the config file.
	log.Lvl3("Setting up the simulations")
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	params := bfv.DefaultParams[0]

	ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	crpGenerator := ring.NewCRPGenerator(nil, ctxPQ)
	modulus := params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGenerator.ClockNew()
	}
	CRP.A = crp

	return sc, nil
}

func (s *RelinearizationKeySimulation) Node(config *onet.SimulationConfig) error {
	idx, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if idx < 0 {
		log.Fatal("Error node not found")
	}

	log.Lvl4("Node setup")
	if _, err := config.Server.ProtocolRegister("RelinearizationKeyProtocolSimul", func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
		return NewRelinearizationKeySimul(tni, s)
	}); err != nil {
		log.ErrFatal(err, "Error could not inject parameters")
		return err
	}

	return s.SimulationBFTree.Node(config)
}

func NewRelinearizationKeySimul(tni *onet.TreeNodeInstance, simulation *RelinearizationKeySimulation) (onet.ProtocolInstance, error) {
	protocol, err := proto.NewRelinearizationKey(tni)
	if err != nil {
		return nil, err
	}
	params := bfv.DefaultParams[0]
	sk, err := utils.GetSecretKey(params, tni.ServerIdentity().ID, "")
	if err != nil {
		return nil, err
	}
	relinkey := protocol.(*proto.RelinearizationKeyProtocol)
	relinkey.Params = *bfv.DefaultParams[0]
	relinkey.Crp = CRP
	relinkey.Sk = *sk
	return relinkey, nil
}

func (s *RelinearizationKeySimulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)

	pi, err := config.Overlay.CreateProtocol("RelinearizationKeyProtocolSimul", config.Tree, onet.NilServiceID)
	if err != nil {
		log.Error(err)
		return err
	}

	RelinProtocol := pi.(*proto.RelinearizationKeyProtocol)

	//Now we can start the protocol
	round := monitor.NewTimeMeasure("round")
	now := time.Now()
	err = RelinProtocol.Start()
	defer RelinProtocol.Done()
	if err != nil {
		log.Error("Could not start relinearization protocol : ", err)
		return err
	}

	RelinProtocol.Wait()
	elapsed := time.Since(now)
	round.Record()

	log.Lvl1("Relinearization key generated for ", size)
	log.Lvl1("Elapsed time :", elapsed)

	//if VerifyCorrectness {
	//	err := CheckRelinearization(size, config, RelinProtocol, err)
	//	if err != nil {
	//		return err
	//	}
	//}

	return nil

}

//
//func CheckRelinearization(size int, config *onet.SimulationConfig, RelinProtocol *proto.RelinearizationKeyProtocol, err error) error {
//	i := 0
//	params := bfv.DefaultParams[0]
//	ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
//	tmp0 := params.NewPolyQP()
//	for i < size {
//		si := config.Roster.List[i]
//		sk0, err := utils.GetSecretKey(params, si.ID)
//		if err != nil {
//			log.Error("error : ", err)
//			return err
//		}
//
//		ctxPQ.Add(tmp0, sk0.Get(), tmp0)
//
//		i++
//	}
//	Sk := new(bfv.SecretKey)
//	Sk.Set(tmp0)
//	Pk := bfv.NewKeyGenerator(params).NewPublicKey(Sk)
//	encryptor_pk := bfv.NewEncryptorFromPk(params, Pk)
//	//encrypt some cipher text...
//	PlainText := bfv.NewPlaintext(params)
//	encoder := bfv.NewEncoder(params)
//	expected := params.NewPolyQP()
//	encoder.EncodeUint(expected.Coeffs[0], PlainText)
//	CipherText := encryptor_pk.EncryptNew(PlainText)
//	//multiply it !
//	evaluator := bfv.NewEvaluator(params)
//	MulCiphertext := evaluator.MulNew(CipherText, CipherText)
//	//we want to relinearize MulCiphertexts
//	ExpectedCoeffs := params.NewPolyQP()
//	ctxPQ.MulCoeffs(expected, expected, ExpectedCoeffs)
//	//in the end of relin we should have RelinCipher === ExpectedCoeffs.
//	array := make([]bfv.EvaluationKey, size)
//	//check if the keys are the same for all parties
//	for i := 0; i < size; i++ {
//		relkey := (<-RelinProtocol.ChannelEvalKey).EvaluationKey
//		data, _ := relkey.MarshalBinary()
//		log.Lvl3("Key starting with : ", data[0:25])
//		log.Lvl3("Got one eval key...")
//		array[i] = relkey
//	}
//	err = utils.CompareEvalKeys(array)
//	if err != nil {
//		log.Error("Different relinearization keys : ", err)
//
//		return err
//	}
//	log.Lvl1("Check : all peers have the same key ")
//	rlk := array[0]
//	ResCipher := evaluator.RelinearizeNew(MulCiphertext, &rlk)
//	//decrypt the cipher
//	decryptor := bfv.NewDecryptor(params, Sk)
//	resDecrypted := decryptor.DecryptNew(ResCipher)
//	resDecoded := encoder.DecodeUint(resDecrypted)
//	if !utils.Equalslice(ExpectedCoeffs.Coeffs[0], resDecoded) {
//		log.Error("Decrypted relinearized cipher is not equal to expected plaintext")
//		return err
//	}
//	log.Lvl1("Relinearization Successful :)")
//	return nil
//}
