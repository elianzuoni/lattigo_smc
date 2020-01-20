package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

type RotationKeySim struct {
	onet.SimulationBFTree

	bfv.Rotation
	lt        *utils.LocalTest
	ParamsIdx int
	Params    *bfv.Parameters

	K      int
	RotIdx int
	CRP    protocols.CRP
}

func init() {
	onet.SimulationRegister("RotationKeyProtocol", NewSimulationRotationKey)
}

func NewSimulationRotationKey(config string) (onet.Simulation, error) {
	sim := &RotationKeySim{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	log.Lvl2("New Rotation key simulation ")

	sim.Params = bfv.DefaultParams[sim.ParamsIdx]
	sim.Rotation = bfv.Rotation(sim.RotIdx)
	return sim, nil
}

func (s *RotationKeySim) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	log.Lvl2("Setting up simulation for rotation")
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

	//generate local needed variables...

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

func (s *RotationKeySim) Node(config *onet.SimulationConfig) error {
	if _, err := config.Server.ProtocolRegister("RotationKeySimulation", func(tni *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
		return NewRotationKeySimul(tni, s)
	}); err != nil {
		return errors.New("Error when registering rotation key " + err.Error())
	}

	s.lt = lt
	s.CRP = CRP
	return s.SimulationBFTree.Node(config)
}

func NewRotationKeySimul(tni *onet.TreeNodeInstance, sim *RotationKeySim) (onet.ProtocolInstance, error) {
	log.Lvl2("New Rotation key simul ")
	protocol, err := protocols.NewRotationKey(tni)
	if err != nil {
		return nil, err
	}

	rotation := protocol.(*protocols.RotationKeyProtocol)
	err = rotation.Init(sim.Params, *sim.lt.SecretKeyShares0[tni.ServerIdentity().ID], sim.Rotation, uint64(sim.K), sim.CRP.A)
	return rotation, err
}

func (s *RotationKeySim) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()

	defer func() {
		err := lt.TearDown(true)
		if err != nil {
			log.Error(err)
		}
	}()

	timings := make([]time.Duration, s.Rounds)

	for i := 0; i < s.Rounds; i++ {

		pi, err := config.Overlay.CreateProtocol("RotationKeySimulation", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		rotation := pi.(*protocols.RotationKeyProtocol)
		round := monitor.NewTimeMeasure("round")
		now := time.Now()
		err = rotation.Start()
		defer rotation.Done()
		if err != nil {
			log.Error("Could not start rotation key protocol : ", err)
			return err
		}

		rotation.Wait()
		elapsed := time.Since(now)
		timings[i] = elapsed
		round.Record()

		log.Lvl1("Roation key generated for ", size, " nodes ")
		log.Lvl1("Elapsed time :", elapsed)

		//check for correctness...
		rotkey := rotation.RotKey
		ctxT, _ := ring.NewContextWithParams(1<<s.Params.LogN, []uint64{s.Params.T})
		coeffs := ctxT.NewUniformPoly().Coeffs[0]
		pt := bfv.NewPlaintext(s.Params)
		enc := bfv.NewEncoder(s.Params)
		enc.EncodeUint(coeffs, pt)
		ciphertext := bfv.NewEncryptorFromSk(s.Params, lt.IdealSecretKey0).EncryptNew(pt)
		evaluator := bfv.NewEvaluator(s.Params)
		n := 1 << s.Params.LogN
		mask := uint64(n>>1) - 1
		expected := make([]uint64, n)

		switch s.Rotation {
		case bfv.RotationRow:
			evaluator.RotateRows(ciphertext, &rotkey, ciphertext)
			expected = append(coeffs[n>>1:], coeffs[:n>>1]...)

			break
		case bfv.RotationRight:

			log.Fatal("Not implemented correctness verification. ")

		case bfv.RotationLeft:
			evaluator.RotateColumns(ciphertext, uint64(s.K), &rotkey, ciphertext)
			for i := uint64(0); i < uint64(n)>>1; i++ {
				expected[i] = coeffs[(i+uint64(s.K))&mask]
				expected[i+uint64(n>>1)] = coeffs[((i+uint64(s.K))&mask)+uint64(n>>1)]
			}
			break
		}
		resultingPt := bfv.NewDecryptor(s.Params, lt.IdealSecretKey0).DecryptNew(ciphertext)

		decoded := enc.DecodeUint(resultingPt)

		if !utils.Equalslice(expected, decoded) {
			log.Error("Decryption failed")
			return errors.New("decryption failed ")
		}

		<-time.After(500 * time.Millisecond)
	}

	log.Lvl1("Success")
	avg := time.Duration(0)
	for _, t := range timings {
		avg += t
	}
	avg /= time.Duration(s.Rounds)
	log.Lvl1("Average time : ", avg)

	return nil

}
