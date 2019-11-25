package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

const ServiceName = "LattigoSMC"

//Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor

	//todo here add more features.
	bfv.Ciphertext
	bfv.PublicKey
	bfv.SecretKey
}

type SetupRequest struct {
	Roster onet.Roster

	GenerateEvaluationKey bool //it was available in gomomorphic hence it may have some uses.
}

//Query a query that a client can make to the service
type Query struct {
	bfv.Ciphertext
}

//MsgTypes different messages that can be used for the service.
type MsgTypes struct {
}

func init() {
	_, err := onet.RegisterNewService(ServiceName, NewLattigoSMCService)
	if err != nil {
		log.Error("Could not start the service")
		panic(err)
	}

}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	newLattigo := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return newLattigo, nil
}

//Setup is done when the processes join the network. Need to generate Collective public key, Collective relin key,
func (s *Service) Setup(request *SetupRequest) (*bfv.PublicKey, *bfv.EvaluationKey, error) {
	log.Lvl1(s.ServerIdentity(), "new setup request")
	tree := request.Roster.GenerateBinaryTree()
	log.Lvl1("Begin new setup with ", tree.Size(), " parties")

	//check if the request comes from root ~ maybe not necessary.
	if !tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {
		return nil, nil, errors.New("ClientSetup request should be sent to a server of the roster.")
	}

	//Collective Key Generation
	log.Lvl1("Starting collective key generation!")
	tni := s.NewTreeNodeInstance(tree, tree.Root, "CollectiveKeyGeneration")
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		panic(err)
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.ErrFatal(err, "Could not register protocol instance")
	}

	//todo here inject parameters.
	err = ckgp.Start()
	if err != nil {
		log.ErrFatal(err, "COuld not start collective key generation protocol")

	}
	//we should wait until the above is done.
	ckgp.Wait()

	publickey := (<-ckgp.ChannelPublicKey).PublicKey
	return &publickey, nil, nil

}

func (s *Service) Process(msg *network.Envelope) {
	//Processor interface used to recognize messages between servers
}

//Query handlers queries can be : Multiply, Add, store

type StoreQuery struct {
	data []byte
	//maybe more is needed.
}

func (s *Service) HandleStoreQuery(storeQuery *StoreQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), ": got a query to store data")

	return nil, nil
}

func (s *Service) HandleSumQuery() (network.Message, error) {
	return nil, nil
}

func (s *Service) HandleMultiplyQuery() (network.Message, error) {
	return nil, nil
}

//Protocol handlers

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tn.SetConfig(conf)
	if err != nil {
		return nil, err
	}
	var protocol onet.ProtocolInstance
	switch tn.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol ckgp")
		protocol, err = protocols.NewCollectiveKeyGeneration(tn)
		if err != nil {
			return nil, err
		}
		keygen := protocol.(*protocols.CollectiveKeyGenerationProtocol)
		keygen.Params = bfv.DefaultParams[0]
		if tn.IsRoot() {

		}
	case protocols.CollectiveKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cksp")

	case protocols.CollectivePublicKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cpksp")

	case protocols.RelinearizationKeyProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol rlkp")

	}
	return protocol, nil
}

func (s *Service) StartProtocol(name string) (onet.ProtocolInstance, error) {

	return nil, nil
}
