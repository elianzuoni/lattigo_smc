package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

const ServiceName = "LattigoSMC"

type ServiceState struct {
	QueryID QueryID
}

type ServiceResult struct {
	Data []byte
	//the restuls of a query encrypted with elgamal.
	K kyber.Point
	C kyber.Point
}

//The query for the result.
type QueryResult struct {
	QueryID *QueryID
	public  kyber.Point
}

//ID of query. Should be unique
type QueryID string

//Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor

	//todo here add more features.
	bfv.Ciphertext
	bfv.PublicKey
	bfv.SecretKey
	bfv.EvaluationKey
}

//QueryData contains the information server side for the query.
type QueryData struct {
	QueryID      QueryID
	Roster       onet.Roster
	ClientPubKey kyber.Point
	Source       *network.ServerIdentity

	//what is in the query
	sum      bool
	multiply bool
	data     []byte
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
	msgQueryData     network.MessageTypeID
	msgSetupRequest  network.MessageTypeID
	msgQuery         network.MessageTypeID
	msgSumQuery      network.MessageTypeID
	msgMultiplyQuery network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	_, err := onet.RegisterNewService(ServiceName, NewLattigoSMCService)
	if err != nil {
		log.Error("Could not start the service")
		panic(err)
	}

	//Register the messages
	log.Lvl1("Registering messages")
	msgTypes.msgQuery = network.RegisterMessage(&Query{})
	msgTypes.msgQueryData = network.RegisterMessage(&QueryData{})
	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{})
	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{})

}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting lattigo smc service")
	newLattigo := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	//registering the handlers
	if err := newLattigo.RegisterHandler(newLattigo.HandleQueryData); err != nil {
		return nil, errors.New("Wrong handler 1:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSumQuery); err != nil {
		return nil, errors.New("Wrong handler 2:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleMultiplyQuery); err != nil {
		return nil, errors.New("Wrong handler 3:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleStoreQuery); err != nil {
		return nil, errors.New("Wrong handler 4:" + err.Error())
	}

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryData)
	c.RegisterProcessor(newLattigo, msgTypes.msgQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)

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
	ckgp.Params = bfv.DefaultParams[0]
	if err != nil {
		log.ErrFatal(err, "Could not start collective key generation protocol")

	}
	//we should wait until the above is done.
	ckgp.Wait()

	publickey := (<-ckgp.ChannelPublicKey).PublicKey
	return &publickey, nil, nil

}

func (s *Service) Process(msg *network.Envelope) {
	//Processor interface used to recognize messages between server
	//idea is to make an if else and send it to the appropriate handler.

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

type SumQuery struct {
	amt uint32
}

func (s *Service) HandleSumQuery(sumQuery *SumQuery) (network.Message, error) {
	return nil, nil
}

type MultiplyQuery struct {
	amt uint32
}

func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
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

//------------HANDLES-QUERIES ---------------
//HandleQueryData is called by the service when the client makes a request to write some data.
func (s *Service) HandleQueryData(query *QueryData) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), " received query data ")
	return nil, nil
}
