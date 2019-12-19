package test

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
	"time"
)

func TestNewRelinearizationKeyLocal(t *testing.T) {
	/**VARIABLES TO TEST ***/
	var nbnodes = 7
	const SKHash = "sk0"
	var VerifyCorrectness = false
	var params = bfv.DefaultParams[0]
	var storageDirectory = "tmp"

	//first generate a secret key and from shards and the resulting public key
	log.SetDebugVisible(1)
	log.Lvl1("Started to test relinearization protocol with nodes amount : ", nbnodes)

	ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	crpGenerator := ring.NewCRPGenerator(nil, ctxPQ)
	modulus := params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGenerator.ClockNew()
	}

	log.Lvl1("Setup ok - Starting protocols")
	if _, err := onet.GlobalProtocolRegister("RelinearizationKeyTestLocal", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		protocol, err := protocols.NewRelinearizationKey(tni)
		if err != nil {
			return nil, err
		}
		sk, err := utils.GetSecretKey(params, tni.ServerIdentity().ID, storageDirectory)
		if err != nil {
			return nil, err
		}
		instance := protocol.(*protocols.RelinearizationKeyProtocol)
		instance.Params = *params
		instance.Sk = *sk
		instance.Crp.A = crp
		return instance, nil
	}); err != nil {
		log.Error("Could not start Relin key protocol : ", err)
		t.Fail()
	}

	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)

	//The parameters are sk,crp,bfvParams
	pi, err := local.CreateProtocol("RelinearizationKeyTestLocal", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	RelinProtocol := pi.(*protocols.RelinearizationKeyProtocol)

	//Now we can start the protocol
	now := time.Now()
	err = RelinProtocol.Start()
	if err != nil {
		log.Error("Could not start relinearization protocol : ", err)
		t.Fail()
	}

	RelinProtocol.Wait()
	elapsed := time.Since(now)
	log.Lvl1("**********RELINEARIZATION KEY PROTOCOL DONE ***************")
	log.Lvl1("**********Time elapsed :", elapsed, "***************")

	if VerifyCorrectness {
		CheckCorrectnessRKG(nbnodes, tree, t, ctxPQ, RelinProtocol, err, SKHash, params)
	}
	RelinProtocol.Done()

}

func TestNewRelinearizationKeyTCP(t *testing.T) {
	/**VARIABLES TO TEST ***/
	var nbnodes = 7
	const SKHash = "sk0"
	var VerifyCorrectness = false
	var params = bfv.DefaultParams[0]
	var storageDirectory = "tmp"

	//first generate a secret key and from shards and the resulting public key
	log.SetDebugVisible(1)
	log.Lvl1("Started to test relinearization protocol TCP with nodes amount : ", nbnodes)

	ctxPQ, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	crpGenerator := ring.NewCRPGenerator(nil, ctxPQ)
	modulus := params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGenerator.ClockNew()
	}

	log.Lvl1("Setup ok - Starting protocols")
	if _, err := onet.GlobalProtocolRegister("RelinearizationKeyTestTCP", func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		protocol, err := protocols.NewRelinearizationKey(tni)
		if err != nil {
			return nil, err
		}
		sk, err := utils.GetSecretKey(params, tni.ServerIdentity().ID, storageDirectory)
		if err != nil {
			return nil, err
		}
		instance := protocol.(*protocols.RelinearizationKeyProtocol)
		instance.Params = *params
		instance.Sk = *sk
		instance.Crp.A = crp
		return instance, nil
	}); err != nil {
		log.Error("Could not start Relin key protocol : ", err)
		t.Fail()
	}

	local := onet.NewTCPTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()
	_, _, tree := local.GenTree(nbnodes, true)

	//The parameters are sk,crp,bfvParams
	pi, err := local.CreateProtocol("RelinearizationKeyTestTCP", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	RelinProtocol := pi.(*protocols.RelinearizationKeyProtocol)

	//Now we can start the protocol
	now := time.Now()
	err = RelinProtocol.Start()
	if err != nil {
		log.Error("Could not start relinearization protocol : ", err)
		t.Fail()
	}

	RelinProtocol.Wait()
	elapsed := time.Since(now)
	log.Lvl1("**********RELINEARIZATION KEY PROTOCOL DONE ***************")
	log.Lvl1("**********Time elapsed :", elapsed, "***************")

	if VerifyCorrectness {
		CheckCorrectnessRKG(nbnodes, tree, t, ctxPQ, RelinProtocol, err, SKHash, params)
	}
	RelinProtocol.Done()

}
