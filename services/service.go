package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

//Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor
	onet.Roster

	//todo here add more features.
	*bfv.Ciphertext
	*bfv.PublicKey
	*bfv.SecretKey
	*bfv.EvaluationKey
	Params             *bfv.Parameters
	pubKeyGenerated    bool
	evalKeyGenerated   bool
	DataBase           map[uuid.UUID]*bfv.Ciphertext
	LocalUUID          map[uuid.UUID]uuid.UUID
	LocalData          map[uuid.UUID]*Transaction
	PendingTransaction chan *Transaction
	KeyReceived        chan bool
	Ckgp               *protocols.CollectiveKeyGenerationProtocol
	crpGen             ring.CRPGenerator
}

type Transaction struct {
	uuid.UUID
	*bfv.Plaintext
	Pending bool
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting lattigo smc service")

	newLattigo := &Service{
		ServiceProcessor:   onet.NewServiceProcessor(c),
		DataBase:           make(map[uuid.UUID]*bfv.Ciphertext),
		LocalUUID:          make(map[uuid.UUID]uuid.UUID),
		LocalData:          make(map[uuid.UUID]*Transaction),
		PendingTransaction: make(chan *Transaction, 10),
		KeyReceived:        make(chan bool),
	}
	//registering the handlers
	if err := newLattigo.RegisterHandler(newLattigo.HandleSendData); err != nil {
		return nil, errors.New("Wrong handler 1:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSumQuery); err != nil {
		return nil, errors.New("Wrong handler 2:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleMultiplyQuery); err != nil {
		return nil, errors.New("Wrong handler 3:" + err.Error())
	}

	if err := newLattigo.RegisterHandler(newLattigo.HandleSetupQuery); err != nil {
		return nil, errors.New("Wrong handler 5: " + err.Error())
	}

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryData)
	c.RegisterProcessor(newLattigo, msgTypes.msgQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyReply)

	c.RegisterProcessor(newLattigo, msgTypes.msgStoreReply)
	go newLattigo.TransactionLoop()
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
		log.Lvl1("Id of cipher : ", tmp.UUID)

		Ack := StoreReply{tmp.UUID, id, true}
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
		log.Lvl1("ID Local , ", tmp.Local, "ID Remote: ", tmp.Remote, "Done :", tmp.Done)
		//Update the local values.
		s.LocalData[tmp.Local].Pending = false
		s.LocalUUID[tmp.Local] = tmp.Remote
		log.Lvl1("Updated value of the ciphertext. ")

	} else if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		log.Lvl1("Got a key request")
		reply := KeyReply{}
		tmp := (msg.Msg).(*KeyRequest)
		if tmp.PublicKey && s.pubKeyGenerated {
			reply.PublicKey = *bfv.NewPublicKey(s.Params)
			reply.PublicKey.Set(s.PublicKey.Get())
		}
		//if tmp.EvaluationKey && s.evalKeyGenerated{
		//	reply.EvaluationKey = *s.EvaluationKey
		//	reply.Flags |= 2
		//
		//}
		//if tmp.RotationKey{
		//	//TODO
		//	reply.Flags |= 4
		//}

		//Send the result.
		err := s.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		log.Lvl1("Got a key reply")
		tmp := (msg.Msg).(*KeyReply)
		if tmp.PublicKey.Get()[0] != nil {
			s.PublicKey = &tmp.PublicKey
			s.KeyReceived <- true
		}
		//if tmp.Flags & 2 > 0 {
		//	s.EvaluationKey = &tmp.EvaluationKey
		//}
		//if tmp.Flags & 4 > 0 {
		//	//todo
		//}

		log.Lvl1("Got the public keys !")

	} else {
		log.Error("Unknown message type :", msg.MsgType)
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
		ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

		//init
		crp := s.crpGen.ClockNew()
		err = ckgp.Init(s.Params, s.SecretKey, crp)

		if !tn.IsRoot() {
			go func() {

				log.Lvl1(s.ServerIdentity(), "Waiting for the protocol to be finished...(NewProtocol)")
				ckgp.Wait()
				log.Lvl1(tn.ServerIdentity(), " : done with collective key gen ! ")

				s.SecretKey = ckgp.Sk
				//s.PublicKey = ckgp.Pk
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

//HandleSendData is called by the service when the client makes a request to write some data.
func (s *Service) HandleSendData(query *QueryData) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), " received query data ")

	data := query.Data
	tree := query.Roster.GenerateBinaryTree()

	if !s.pubKeyGenerated {
		//here we can not yet do the answer
		return nil, errors.New("Key has not yet been generated.")
	}
	if s.PublicKey == nil {
		log.Lvl1("Querying public key to the server")

		keyreq := KeyRequest{PublicKey: true}
		err := s.SendRaw(tree.Root.ServerIdentity, &keyreq)
		if err != nil {
			log.Error("Could not send key request to the root : ", err)
			return nil, err
		}

	}

	encoder := bfv.NewEncoder(s.Params)
	coeffs, err := utils.BytesToUint64(data)
	if err != nil {
		return nil, err
	}
	pt := bfv.NewPlaintext(s.Params)
	encoder.EncodeUint(coeffs, pt)

	id := uuid.NewV1()
	tx := Transaction{
		UUID:      id,
		Plaintext: pt,
		Pending:   true,
	}
	s.LocalData[id] = &tx
	s.PendingTransaction <- &tx

	return &ServiceState{id, true}, nil
}

//Setup is done when the processes join the network. Need to generate Collective public key, Collective relin key,

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

func (s *Service) TransactionLoop() {
	<-s.KeyReceived
	log.Lvl1("Key received starting transaction loop.")
	tree := s.Roster.GenerateBinaryTree()
	//Start the loop only when the public key is done
	for {
		select {
		case tx := <-s.PendingTransaction:

			pt := tx.Plaintext
			//Send it to the server
			encryptorPk := bfv.NewEncryptorFromPk(s.Params, s.PublicKey)
			cipher := encryptorPk.EncryptNew(pt)
			//now we can send this to the root

			err := s.SendRaw(tree.Root.ServerIdentity, &StoreQuery{*cipher, tx.UUID})
			if err != nil {
				log.Error("could not send cipher to the root. ")
			}

			break

		}
	}
}

//TODO Method below

func (s *Service) HandleSumQuery(sumQuery *SumQuery) (network.Message, error) {
	return nil, nil
}

func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	return nil, nil
}
