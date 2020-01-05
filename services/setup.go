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
	log.Lvl1(s.ServerIdentity(), "new setup request")
	tree := request.Roster.GenerateBinaryTree()

	log.Lvl1("Begin new setup with ", tree.Size(), " parties")
	s.Roster = request.Roster
	s.Params = bfv.DefaultParams[request.ParamsIdx]
	s.SecretKey = bfv.NewKeyGenerator(s.Params).GenSecretKey()

	s.crpGen = *dbfv.NewCRPGenerator(s.Params, request.Seed)

	//Collective Key Generation
	if !s.pubKeyGenerated {
		//send the information to the childrens.
		if tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {

			err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, request)
			if err != nil {
				return &SetupReply{-1}, err
			}

			err = s.genPublicKey(tree)

			if err != nil {
				return &SetupReply{-1}, err
			}

		}

	}

	if !request.GenerateEvaluationKey {
		log.Lvl1("Did not request for evaluation key. returning..")
		return &SetupReply{1}, nil

	}
	//Eval key generation
	if !s.evalKeyGenerated {
		err := s.genEvalKey(tree)
		if err != nil {
			return &SetupReply{-1}, err
		}
	}

	log.Lvl1(s.ServerIdentity(), "out ")
	return &SetupReply{1}, nil

}

func (s *Service) genEvalKey(tree *onet.Tree) error {
	//TODO
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
	//inject the parameters.
	rkg.Sk = *s.SecretKey
	rkg.Params = *bfv.DefaultParams[0]
	//rkg.Crp = nil
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
	s.PublicKey = ckgp.Pk
	s.pubKeyGenerated = true
	log.Lvl1(s.ServerIdentity(), " got public key!")
	return nil
}
