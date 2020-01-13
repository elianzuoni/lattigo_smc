package services

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

//------------HANDLES-QUERIES ---------------
func (s *Service) HandleSetupQuery(request *SetupRequest) (network.Message, error) {
	tree := request.Roster.GenerateBinaryTree()

	log.Lvl1("Begin new setup with ", tree.Size(), " parties")
	s.Roster = request.Roster
	s.Params = bfv.DefaultParams[request.ParamsIdx]
	keygen := bfv.NewKeyGenerator(s.Params)
	s.SecretKey = keygen.GenSecretKey()
	s.PublicKey = keygen.GenPublicKey(s.SecretKey)
	s.crpGen = *dbfv.NewCRPGenerator(s.Params, request.Seed)

	requestSent := false

	//Collective Key Generation
	if !s.pubKeyGenerated && request.GeneratePublicKey {
		//send the information to the childrens.
		if tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {
			err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, request)
			if err != nil {
				return &SetupReply{-1}, err
			}
			requestSent = true
			<-time.After(2 * time.Second)
			err = s.genPublicKey(tree)

			if err != nil {
				return &SetupReply{-1}, err
			}

		}

	}

	//Eval key generation
	if request.GenerateEvaluationKey && !s.evalKeyGenerated {
		log.Lvl1("Generate evalutation key ! ")
		if tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {
			if !requestSent {
				err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, request)
				if err != nil {
					return &SetupReply{-1}, err
				}
				requestSent = true
			}

			err := s.genEvalKey(tree)

			if err != nil {
				return &SetupReply{-1}, err
			}

		}
	}

	if request.GenerateRotationKey && !s.rotKeyGenerated[request.RotIdx] {
		s.RotIdx = request.RotIdx
		s.K = request.K
		log.Lvl1("Generate evalutation key ! ")
		if tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {
			if !requestSent {

				err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, request)
				if err != nil {
					return &SetupReply{-1}, err
				}
				requestSent = true
			}

			err := s.genRotKey(tree, request.K, request.RotIdx)

			if err != nil {
				return &SetupReply{-1}, err
			}

		}

	}

	return &SetupReply{1}, nil

}

func (s *Service) genEvalKey(tree *onet.Tree) error {
	log.Lvl1("Starting relinearization key protocol")
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.RelinearizationKeyProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		panic(err)
	}
	rkg := protocol.(*protocols.RelinearizationKeyProtocol)
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		panic(err)
	}
	<-time.After(1 * time.Second)
	err = rkg.Start()
	if err != nil {
		return err
	}

	go rkg.Dispatch()

	rkg.Wait()
	log.Lvl1("Finished relin protocol")

	s.EvaluationKey = rkg.EvaluationKey
	s.evalKeyGenerated = true
	return nil
}

func (s *Service) genPublicKey(tree *onet.Tree) error {
	log.Lvl1(s.ServerIdentity(), "Starting collective key generation!")

	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveKeyGenerationProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		panic(err)
	}
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.ErrFatal(err, "Could not register protocol instance")
	}

	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	<-time.After(1 * time.Second) //dirty hack...

	//if ckgp.IsRoot(){
	err = ckgp.Start()
	if err != nil {
		log.ErrFatal(err, "Could not start collective key generation protocol")
	}
	go ckgp.Dispatch()
	//}

	//we should wait until the above is done.
	log.Lvl1(ckgp.ServerIdentity(), "Waiting for the protocol to be finished :x")
	ckgp.Wait()
	s.SecretKey = ckgp.Sk
	s.Encoder = bfv.NewEncoder(s.Params)
	s.DecryptorSk = bfv.NewDecryptor(s.Params, s.SecretKey)
	s.MasterPublicKey = ckgp.Pk
	s.pubKeyGenerated = true
	log.Lvl1(s.ServerIdentity(), " got public key!")
	return nil
}

func (s *Service) genRotKey(tree *onet.Tree, k uint64, rotIdx int) error {
	log.Lvl1("Starting rotation key protocol")
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.RotationProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		panic(err)
	}
	rotkeygen := protocol.(*protocols.RotationKeyProtocol)
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		panic(err)
	}
	<-time.After(1 * time.Second)
	err = rotkeygen.Start()
	if err != nil {
		return err
	}

	go rotkeygen.Dispatch()

	rotkeygen.Wait()
	log.Lvl1("Finished relin protocol")

	s.RotationKey[rotIdx] = rotkeygen.RotKey
	s.rotKeyGenerated[rotIdx] = true
	return nil
}
