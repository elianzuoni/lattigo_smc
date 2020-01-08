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

	*bfv.Ciphertext
	MasterPublicKey *bfv.PublicKey
	*bfv.SecretKey
	*bfv.PublicKey
	*bfv.EvaluationKey
	Params *bfv.Parameters

	Decryptor bfv.Decryptor
	Encoder   bfv.Encoder
	Encryptor bfv.Encryptor

	pubKeyGenerated     bool
	evalKeyGenerated    bool
	DataBase            map[uuid.UUID]*bfv.Ciphertext
	LocalUUID           map[uuid.UUID]chan uuid.UUID
	Ckgp                *protocols.CollectiveKeyGenerationProtocol
	crpGen              ring.CRPGenerator
	SwitchedCiphertext  map[uuid.UUID]chan bfv.Ciphertext
	SwitchingParameters chan SwitchingParamters
}

type SwitchingParamters struct {
	bfv.PublicKey
	bfv.Ciphertext
}

type Transaction struct {
	uuid.UUID
	*bfv.Plaintext
	Pending bool
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting lattigo smc service")

	newLattigo := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		DataBase:         make(map[uuid.UUID]*bfv.Ciphertext),
		LocalUUID:        make(map[uuid.UUID]chan uuid.UUID),
		//LocalData:          make(map[uuid.UUID]*Transaction),
		//PendingTransaction: make(chan *Transaction, 10),
		//KeyReceived:        make(chan bool),
		SwitchedCiphertext:  make(map[uuid.UUID]chan bfv.Ciphertext),
		SwitchingParameters: make(chan SwitchingParamters, 10),
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

	if err := newLattigo.RegisterHandler(newLattigo.HandlePlaintextQuery); err != nil {
		return nil, errors.New("Wrong handler 7 : " + err.Error())
	}

	if err := newLattigo.RegisterHandler(newLattigo.HandleKeyRequest); err != nil {
		return nil, errors.New("Wrong handler 8 : " + err.Error())
	}

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryData)
	c.RegisterProcessor(newLattigo, msgTypes.msgQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyReply)

	c.RegisterProcessor(newLattigo, msgTypes.msgStoreReply)

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryPlaintext)
	c.RegisterProcessor(newLattigo, msgTypes.msgReplyPlaintext)
	return newLattigo, nil
}

func (s *Service) Process(msg *network.Envelope) {
	//Processor interface used to recognize messages between server
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
		s.LocalUUID[tmp.Local] = make(chan uuid.UUID, 1)
		s.LocalUUID[tmp.Local] <- tmp.Remote
		log.Lvl1("Updated value of the ciphertext. ")

	} else if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		log.Lvl1("Got a key request")
		reply := KeyReply{}
		tmp := (msg.Msg).(*KeyRequest)
		if tmp.PublicKey && s.pubKeyGenerated {
			reply.PublicKey = *bfv.NewPublicKey(s.Params)
			reply.PublicKey.Set(s.MasterPublicKey.Get())
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
			s.MasterPublicKey = &tmp.PublicKey
		}
		//if tmp.Flags & 2 > 0 {
		//	s.EvaluationKey = &tmp.EvaluationKey
		//}
		//if tmp.Flags & 4 > 0 {
		//	//todo
		//}

		log.Lvl1("Got the public keys !")

	} else if msg.MsgType.Equal(msgTypes.msgReplyPlaintext) {
		log.Lvl1("Got a ciphertext switched")
		tmp := (msg.Msg).(*ReplyPlaintext)
		s.SwitchedCiphertext[tmp.UUID] <- tmp.Ciphertext
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
				s.PublicKey = bfv.NewKeyGenerator(s.Params).GenPublicKey(s.SecretKey)
				s.pubKeyGenerated = true
			}()

		}
	case protocols.CollectiveKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cksp")

	case protocols.CollectivePublicKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cpksp")
		protocol, err = protocols.NewCollectivePublicKeySwitching(tn)
		if err != nil {
			return nil, err
		}
		pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)
		var publickey bfv.PublicKey
		var ciphertext *bfv.Ciphertext
		sp := <-s.SwitchingParameters
		publickey = sp.PublicKey
		ciphertext = &sp.Ciphertext
		err = pcks.Init(*s.Params, publickey, *s.SecretKey, ciphertext)
		if err != nil {
			return nil, err
		}

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

//TODO Method below

func (s *Service) HandlePlaintextQuery(query *QueryPlaintext) (network.Message, error) {
	//Initiate the CKS
	log.Lvl1(s.ServerIdentity(), "got request for plaintext of id : ", query.UUID)
	tree := s.GenerateBinaryTree()
	inner := query.Innermessage
	if query.Innermessage {
		//From the client Send it to all the other peers so they can initate the PCKS
		query.Innermessage = false
		query.PublicKey = *s.PublicKey
		query.Origin = s.ServerIdentity()

		err := s.SendRaw(tree.Root.ServerIdentity, query)

		if err != nil {
			log.Error("Could not send the initation message to all other peers")
			return nil, err
		}

	}

	//it comes from either the initiator or the root.
	if s.ServerIdentity().Equal(tree.Root.ServerIdentity) {
		//The root has to propagate to all members the ciphertext and the public key...
		//Get the ciphertext.
		cipher := s.DataBase[query.UUID]
		query.Ciphertext = *cipher
		//Send to all

		err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, &query)
		if err != nil {
			return nil, err
		}
		//Start the key switch
		reply, err := s.switchKeys(tree, query.Origin, query.UUID)
		if err != nil {
			log.Error("Could not switch key : ", err)
		}
		return reply, err

	} else if !inner {
		//Initialize all of the values and return
		params := SwitchingParamters{
			PublicKey:  query.PublicKey,
			Ciphertext: query.Ciphertext,
		}
		s.SwitchingParameters <- params
		return &SetupReply{1}, nil

	} else {
		//Wait for CKS to complete

		cipher := <-s.SwitchedCiphertext[query.UUID]

		plain := s.Decryptor.DecryptNew(&cipher)

		data64 := s.Encoder.DecodeUint(plain)
		bytes, err := utils.Uint64ToBytes(data64)
		if err != nil {
			log.Error("Could not retrieve byte array : ", err)
		}
		response := &QueryData{Id: query.UUID, Data: bytes}

		return response, nil
	}

}

func (s *Service) HandleSumQuery(sumQuery *SumQuery) (network.Message, error) {
	return nil, nil
}

func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	return nil, nil
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
