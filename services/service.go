package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

//ID of query. Should be unique

//Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor
	onet.Roster

	//todo here add more features.
	*bfv.Ciphertext
	*bfv.PublicKey
	*bfv.SecretKey
	*bfv.EvaluationKey
	Params           *bfv.Parameters
	pubKeyGenerated  bool
	evalKeyGenerated bool
	DataBase         map[uuid.UUID]*bfv.Ciphertext
}

//MsgTypes different messages that can be used for the service.
type MsgTypes struct {
	msgQueryData     network.MessageTypeID
	msgSetupRequest  network.MessageTypeID
	msgQuery         network.MessageTypeID
	msgSumQuery      network.MessageTypeID
	msgMultiplyQuery network.MessageTypeID
	msgStoreReply    network.MessageTypeID
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
	msgTypes.msgQuery = network.RegisterMessage(&StoreQuery{})
	msgTypes.msgQueryData = network.RegisterMessage(&QueryData{})
	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{})
	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{})

	msgTypes.msgStoreReply = network.RegisterMessage(&StoreReply{})
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
	if err := newLattigo.RegisterHandler(newLattigo.HandleSetupQuery); err != nil {
		return nil, errors.New("Wrong handler 5: " + err.Error())
	}

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryData)
	c.RegisterProcessor(newLattigo, msgTypes.msgQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)

	return newLattigo, nil
}

func (s *Service) Process(msg *network.Envelope) {
	//Processor interface used to recognize messages between server
	//idea is to make an if else and send it to the appropriate handler.
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		log.Lvl1(s.ServerIdentity(), "got a setup message! (in process) ")
		tmp := (msg.Msg).(*SetupRequest)
		_, err := s.HandleSetupQuery(tmp)
		if err != nil {
			log.Error(err)
		}
	} else if msg.MsgType.Equal(msgTypes.msgQuery) {
		//query to store data..
		log.Lvl1(s.ServerIdentity(), "got a request to store a cipher")
		tmp := (msg.Msg).(*StoreQuery)
		id := uuid.NewV1()
		s.DataBase[id] = &tmp.Ciphertext
		//send an acknowledgement of storing..
		sender := msg.ServerIdentity
		Ack := StoreReply{tmp.Id, true}
		err := s.SendRaw(sender, &Ack)
		if err != nil {
			log.Error("Could not send acknowledgement")
		}
		log.Lvl1("Sent an acknowledgement to  ", sender.String())
	} else if msg.MsgType.Equal(msgTypes.msgQueryData) {

	} else if msg.MsgType.Equal(msgTypes.msgMultiplyQuery) {

	} else if msg.MsgType.Equal(msgTypes.msgSumQuery) {

	} else if msg.MsgType.Equal(msgTypes.msgStoreReply) {
		log.Lvl1("Got a store reply")
		tmp := (msg.Msg).(*StoreReply)
		log.Lvl1("ID : ", tmp.Id, "Done :", tmp.Done)
		//Send it back to the client.

	}

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

		if !tn.IsRoot() {
			go func() {
				ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)
				log.Lvl1("Waiting for the protocol to be finished...")
				ckgp.Wait()
				log.Lvl1(tn.ServerIdentity(), " : done with collective key gen ! ")

				s.SecretKey = ckgp.Sk
				s.PublicKey = ckgp.Pk
				s.pubKeyGenerated = true
			}()

		}
	case protocols.CollectiveKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cksp")

	case protocols.CollectivePublicKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cpksp")

	case protocols.RelinearizationKeyProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol rlkp")
		protocol, err = protocols.NewRelinearizationKey(tn)
		if err != nil {
			return nil, err
		}
		if tn.IsRoot() {
			//has to generate the CRP for all other nodes.

		}

	}
	return protocol, nil
}

//------------HANDLES-QUERIES ---------------
//HandleQueryData is called by the service when the client makes a request to write some data.
func (s *Service) HandleQueryData(query *QueryData) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), " received query data ")

	data := query.Data
	if !s.pubKeyGenerated {
		//here we can not yet do the answer
		return nil, errors.New("Key has not yet been generated.")
	}
	params := bfv.DefaultParams[0]
	encoder := bfv.NewEncoder(params)
	coeffs, err := utils.BytesToUint64(data)
	if err != nil {
		return nil, err
	}
	pt := bfv.NewPlaintext(params)
	encoder.EncodeUint(coeffs, pt)
	encryptorPk := bfv.NewEncryptorFromPk(params, s.PublicKey)
	cipher := encryptorPk.EncryptNew(pt)
	//now we can send this to the root
	tree := query.Roster.GenerateBinaryTree()

	err = s.SendRaw(tree.Root.ServerIdentity, &StoreQuery{uuid.UUID{}, *cipher})
	if err != nil {
		log.Error("could not send cipher to the root. ")
	}
	return &ServiceState{uuid.UUID{}, true}, nil
}

func (s *Service) HandleStoreQuery(storeQuery *StoreQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), ": got a query to store data")
	return nil, nil
}

func (s *Service) HandleSumQuery(sumQuery *SumQuery) (network.Message, error) {
	return nil, nil
}

func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	return nil, nil
}

//Setup is done when the processes join the network. Need to generate Collective public key, Collective relin key,
func (s *Service) HandleSetupQuery(request *SetupRequest) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "new setup request")
	tree := request.Roster.GenerateBinaryTree()
	log.Lvl1("Begin new setup with ", tree.Size(), " parties")

	//Collective Key Generation
	if !s.pubKeyGenerated {
		//send the information to the childrens.
		if tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {
			err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, request)
			if err != nil {
				return &SetupReply{-1}, err
			}
		}

		s.Roster = request.Roster
		s.Params = bfv.DefaultParams[request.ParamsIdx]
		s.SecretKey = bfv.NewSecretKey(s.Params)

		seed := &request.Seed
		<-time.After(3 * time.Second)
		err := s.genPublicKey(tree, *seed)

		if err != nil {
			return &SetupReply{-1}, err
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

	log.Lvl1(s.ServerIdentity(), "")
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

func (s *Service) genPublicKey(tree *onet.Tree, seed []byte) error {
	log.Lvl1("Starting collective key generation!")
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveKeyGenerationProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		panic(err)
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	//init
	crpGen := dbfv.NewCRPGenerator(s.Params, seed)
	crp := crpGen.ClockNew()

	err = ckgp.Init(s.Params, s.SecretKey, crp)
	if err != nil {
		panic(err)
	}

	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.ErrFatal(err, "Could not register protocol instance")
	}
	go ckgp.Dispatch()

	//we should wait until the above is done.
	log.Lvl1("Waiting for the protocol to be finished...")
	ckgp.Wait()
	s.SecretKey = ckgp.Sk
	s.PublicKey = ckgp.Pk
	s.pubKeyGenerated = true
	log.Lvl1(s.ServerIdentity(), " got public key!")
	return nil
}

/*************UNUSED FOR NOW ******************/

func (s *Service) StartProtocol(name string) (onet.ProtocolInstance, error) {
	log.Lvl1(s.ServerIdentity(), ": starts protocol :", name)
	tree := s.GenerateBigNaryTree(2, len(s.Roster.List))
	tni := s.NewTreeNodeInstance(tree, tree.Root, name)
	var conf onet.GenericConfig //todo what is the config ?
	protocol, err := s.NewProtocol(tni, &conf)
	if err != nil {
		return nil, errors.New("Error runnning " + name + ": " + err.Error())
	}
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		return nil, err
	}
	go func(protoname string) {
		err := protocol.Dispatch()
		if err != nil {
			log.Error("Error in dispatch : ", err)
		}
	}(name)

	go func(protoname string) {
		err := protocol.Start()
		if err != nil {
			log.Error("Error on start :", err)
		}
	}(name)

	return protocol, nil
}
