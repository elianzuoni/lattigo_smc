//This file holds the Relinearization key protocol
//Contains all method that are implemented in order to implement a protocol from onet.
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

type RelinearizationKeySimulation struct {
	onet.SimulationBFTree
	proto.CRP

	lt        *utils.LocalTest
	ParamsIdx int
	Params    *bfv.Parameters
}

var CRP proto.CRP

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
	sim.Params = bfv.DefaultParams[sim.ParamsIdx]

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
	s.lt, err = utils.GetLocalTestForRoster(sc.Roster, s.Params, storageDir)
	if err != nil {
		return nil, err
	}
	lt = s.lt

	params := s.Params
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
	s.lt = lt
	s.CRP = CRP

	return s.SimulationBFTree.Node(config)
}

func NewRelinearizationKeySimul(tni *onet.TreeNodeInstance, simulation *RelinearizationKeySimulation) (onet.ProtocolInstance, error) {
	protocol, err := proto.NewRelinearizationKey(tni)
	if err != nil {
		return nil, err
	}

	relinkey := protocol.(*proto.RelinearizationKeyProtocol)

	err = relinkey.Init(*simulation.Params, *simulation.lt.SecretKeyShares0[tni.ServerIdentity().ID], simulation.CRP.A)
	return relinkey, nil
}

func (s *RelinearizationKeySimulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	defer func() {
		err := lt.TearDown(true)
		if err != nil {
			log.Error(err)
		}
	}()

	log.Lvl4("Size : ", size, " rounds : ", s.Rounds)
	timings := make([]time.Duration, s.Rounds)
	for i := 0; i < s.Rounds; i++ {

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
		timings[i] = elapsed
		round.Record()

		log.Lvl1("Relinearization key generated for ", size)
		log.Lvl1("Elapsed time :", elapsed)

		sk := lt.IdealSecretKey0
		pk := bfv.NewKeyGenerator(s.Params).GenPublicKey(sk)
		encryptor_pk := bfv.NewEncryptorFromPk(s.Params, pk)
		encoder := bfv.NewEncoder(s.Params)

		pt := bfv.NewPlaintext(s.Params)
		expected := s.Params.NewPolyQP()
		encoder.EncodeUint(expected.Coeffs[0], pt)
		CipherText := encryptor_pk.EncryptNew(pt)
		//multiply it !
		evaluator := bfv.NewEvaluator(s.Params)
		MulCiphertext := evaluator.MulNew(CipherText, CipherText)
		//we want to relinearize MulCiphertexts
		ExpectedCoeffs := s.Params.NewPolyQP()
		ctxPQ, _ := ring.NewContextWithParams(1<<s.Params.LogN, append(s.Params.Moduli.Qi, s.Params.Moduli.Pi...))
		ctxPQ.MulCoeffs(expected, expected, ExpectedCoeffs)
		evalkey := RelinProtocol.EvaluationKey
		ResCipher := evaluator.RelinearizeNew(MulCiphertext, evalkey)

		decryptor := bfv.NewDecryptor(s.Params, sk)
		resDecrypted := decryptor.DecryptNew(ResCipher)
		resDecoded := encoder.DecodeUint(resDecrypted)
		if !utils.Equalslice(ExpectedCoeffs.Coeffs[0], resDecoded) {
			log.Error("Decryption failed")
			return errors.New("decryption failed")
		}
		<-time.After(500 * time.Millisecond)
	}
	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(s.Rounds)
	log.Lvl1("Average time : ", avg)
	return nil

}
