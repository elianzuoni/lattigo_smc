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

	DecryptorSk bfv.Decryptor
	Encoder     bfv.Encoder
	Encryptor   bfv.Encryptor

	pubKeyGenerated     bool
	evalKeyGenerated    bool
	rotKeyGenerated     []bool
	DataBase            map[uuid.UUID]*bfv.Ciphertext
	LocalUUID           map[uuid.UUID]chan uuid.UUID
	Ckgp                *protocols.CollectiveKeyGenerationProtocol
	crpGen              ring.CRPGenerator
	SwitchedCiphertext  map[uuid.UUID]chan bfv.Ciphertext
	SwitchingParameters chan SwitchingParamters
	RotationKey         []bfv.RotationKeys

	SumReplies      map[SumQuery]chan uuid.UUID
	MultiplyReplies map[MultiplyQuery]chan uuid.UUID
	RotationReplies map[uuid.UUID]chan uuid.UUID

	RefreshParams chan *bfv.Ciphertext
	RotIdx        int
	K             uint64
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

		SwitchedCiphertext:  make(map[uuid.UUID]chan bfv.Ciphertext),
		SwitchingParameters: make(chan SwitchingParamters, 10),
		RotationKey:         make([]bfv.RotationKeys, 3),
		rotKeyGenerated:     make([]bool, 3),

		SumReplies:      make(map[SumQuery]chan uuid.UUID),
		MultiplyReplies: make(map[MultiplyQuery]chan uuid.UUID),
		RefreshParams:   make(chan *bfv.Ciphertext),
		RotationReplies: make(map[uuid.UUID]chan uuid.UUID),
	}
	//registering the handlers
	e := registerHandlers(newLattigo)
	if e != nil {
		return nil, e
	}
	registerProcessors(c, newLattigo)

	return newLattigo, nil
}

func registerHandlers(newLattigo *Service) error {
	if err := newLattigo.RegisterHandler(newLattigo.HandleSendData); err != nil {
		return errors.New("Wrong handler 1:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSumQuery); err != nil {
		return errors.New("Wrong handler 2:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleMultiplyQuery); err != nil {
		return errors.New("Wrong handler 3:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSetupQuery); err != nil {
		return errors.New("Wrong handler 5: " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandlePlaintextQuery); err != nil {
		return errors.New("Wrong handler 7 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleKeyRequest); err != nil {
		return errors.New("Wrong handler 8 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleRelinearizationQuery); err != nil {
		return errors.New("Wrong handler 9 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleRefreshQuery); err != nil {
		return errors.New("Wrong handler 10 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleRotationQuery); err != nil {
		return errors.New("Wrong handler 11 : " + err.Error())
	}
	return nil
}

func registerProcessors(c *onet.Context, newLattigo *Service) {
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgStoreQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgStoreReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgQueryPlaintext)
	c.RegisterProcessor(newLattigo, msgTypes.msgReplyPlaintext)
	c.RegisterProcessor(newLattigo, msgTypes.msgSumQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSumReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgMultiplyQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgMultiplyReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgRelinQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgRefreshQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgRotationQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgRotationReply)
}

//Process a message from an other service. This is a big if-else-if loop over all type of messages that can be received.
func (s *Service) Process(msg *network.Envelope) {
	//TODO HUUGE REFACTORING NEEDED HERE !!!
	//Processor interface used to recognize messages between server
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		log.Lvl1(s.ServerIdentity(), "got a setup message! (in process) ")
		tmp := (msg.Msg).(*SetupRequest)
		_, err := s.HandleSetupQuery(tmp)

		if err != nil {
			log.Error(err)
		}
	} else if msg.MsgType.Equal(msgTypes.msgStoreQuery) {
		//query to store data..
		log.Lvl1(s.ServerIdentity(), "got a request to store a cipher")
		tmp := (msg.Msg).(*StoreQuery)
		id := uuid.NewV1()
		s.DataBase[id] = tmp.Ciphertext
		//send an acknowledgement of storing..
		sender := msg.ServerIdentity
		log.Lvl1("Id of cipher : ", tmp.UUID)

		Ack := StoreReply{tmp.UUID, id, true}
		err := s.SendRaw(sender, &Ack)
		if err != nil {
			log.Error("Could not send acknowledgement")
		}
		log.Lvl1("Sent an acknowledgement to  ", sender.String())

		//} else if msg.MsgType.Equal(msgTypes.msgStoreQueryClient) {

	} else if msg.MsgType.Equal(msgTypes.msgMultiplyQuery) {

		log.Lvl1("Got request to multiply two ciphertexts")
		tmp := (msg.Msg).(*MultiplyQuery)
		log.Lvl1("Multply :", tmp.UUID, "+", tmp.Other)
		eval := bfv.NewEvaluator(s.Params)
		ct1, ok := s.DataBase[tmp.UUID]
		if !ok {
			log.Error("Ciphertext ", tmp.UUID, " does not exist.")
			return
		}

		ct2, ok := s.DataBase[tmp.Other]
		if !ok {
			log.Error("Ciphertext ", tmp.UUID, " does not exist.")
			return
		}
		id := uuid.NewV1()
		s.DataBase[id] = eval.MulNew(ct1, ct2)
		reply := MultiplyReply{id, *tmp}
		log.Lvl1("Storing result in : ", id)
		err := s.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not reply to the server ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		tmp := (msg.Msg).(*MultiplyReply)
		log.Lvl1("Got reply of multiply query : ", tmp.UUID)

		s.MultiplyReplies[tmp.MultiplyQuery] <- tmp.UUID

	} else if msg.MsgType.Equal(msgTypes.msgSumQuery) {
		log.Lvl1("Got request to sum up ciphertexts")
		tmp := (msg.Msg).(*SumQuery)
		log.Lvl1("Sum :", tmp.UUID, "+", tmp.Other)
		eval := bfv.NewEvaluator(s.Params)
		ct1, ok := s.DataBase[tmp.UUID]
		if !ok {
			log.Error("Ciphertext ", tmp.UUID, " does not exist.")
			return
		}

		ct2, ok := s.DataBase[tmp.Other]
		if !ok {
			log.Error("Ciphertext ", tmp.UUID, " does not exist.")
			return
		}
		id := uuid.NewV1()
		s.DataBase[id] = eval.AddNew(ct1, ct2)
		reply := SumReply{id, *tmp}
		err := s.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not reply to the server ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgSumReply) {
		log.Lvl1("Got message for sum reply")
		tmp := (msg.Msg).(*SumReply)
		s.SumReplies[tmp.SumQuery] <- tmp.UUID
	} else if msg.MsgType.Equal(msgTypes.msgRotationQuery) {
		log.Lvl1("Got request for rotation !")
		tmp := (msg.Msg).(*RotationQuery)
		rotIdx := tmp.RotIdx
		K := tmp.K
		id := tmp.UUID
		if !s.rotKeyGenerated[rotIdx] {
			return
		}
		eval := bfv.NewEvaluator(s.Params)
		cipher, ok := s.DataBase[id]
		if !ok {
			log.Error("Ciphertext does not exist : ", id)
			return
		}
		newId := uuid.NewV1()
		switch bfv.Rotation(rotIdx) {
		case bfv.RotationRow:
			s.DataBase[newId] = eval.RotateRowsNew(cipher, &s.RotationKey[rotIdx])
		case bfv.RotationLeft:
			s.DataBase[newId] = eval.RotateColumnsNew(cipher, K, &s.RotationKey[rotIdx])
		case bfv.RotationRight:
			s.DataBase[newId] = eval.RotateColumnsNew(cipher, K, &s.RotationKey[rotIdx])
		}
		reply := RotationReply{id, newId}
		err := s.SendRaw(msg.ServerIdentity, &reply)
		log.Lvl1("Sent result of rotaiton :) ")
		if err != nil {
			log.Error("Could not rotate ciphertext : ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		log.Lvl1("Got rotation replies")
		tmp := (msg.Msg).(*RotationReply)
		s.RotationReplies[tmp.Old] <- tmp.New

	} else if msg.MsgType.Equal(msgTypes.msgRelinQuery) {
		log.Lvl1("Got relin query")
		tmp := (msg.Msg).(*RelinQuery)
		ct, ok := s.DataBase[tmp.UUID]
		if !ok {
			log.Error("query for ciphertext that does not exist : ", tmp.UUID)
			return
		}
		if !s.evalKeyGenerated {
			log.Error("evaluation key not generated aborting")
			return
		}

		eval := bfv.NewEvaluator(s.Params)
		ct1 := eval.RelinearizeNew(ct, s.EvaluationKey)
		s.DataBase[tmp.UUID] = ct1
		log.Lvl1("Relinearization done")
		return
	} else if msg.MsgType.Equal(msgTypes.msgRefreshQuery) {
		tmp := (msg.Msg).(*RefreshQuery)
		log.Lvl1("Got refresh query for cipher :", tmp.UUID)

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
			reply.PublicKey = (s.MasterPublicKey)
		}
		if tmp.EvaluationKey && s.evalKeyGenerated {
			reply.EvaluationKey = s.EvaluationKey

		}
		if tmp.RotationKey && s.rotKeyGenerated[tmp.RotIdx] {
			reply.RotationKeys = &s.RotationKey[tmp.RotIdx]
		}

		//Send the result.
		err := s.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		log.Lvl1("Got a key reply")
		tmp := (msg.Msg).(*KeyReply)
		if tmp.PublicKey != nil {
			s.MasterPublicKey = tmp.PublicKey
		}
		if tmp.EvaluationKey != nil {
			s.EvaluationKey = tmp.EvaluationKey
		}
		if tmp.RotationKeys != nil {
			s.RotationKey[tmp.RotIdx] = *tmp.RotationKeys
		}

		log.Lvl1("Got the public keys !")

	} else if msg.MsgType.Equal(msgTypes.msgReplyPlaintext) {
		tmp := (msg.Msg).(*ReplyPlaintext)
		log.Lvl1("Got a ciphertext switched with UUID : ", tmp.UUID)

		s.SwitchedCiphertext[tmp.UUID] = make(chan bfv.Ciphertext, 1)
		s.SwitchedCiphertext[tmp.UUID] <- *tmp.Ciphertext
	} else if msg.MsgType.Equal(msgTypes.msgQueryPlaintext) {
		//it comes from either the initiator or the root.
		tree := s.Roster.GenerateBinaryTree()
		query := (msg.Msg).(*QueryPlaintext)

		log.Lvl1("Got a query for ciphertext switching : ", query.UUID)

		if s.ServerIdentity().Equal(tree.Root.ServerIdentity) {
			//The root has to propagate to all members the ciphertext and the public key...
			//Get the ciphertext.
			cipher := s.DataBase[query.UUID]
			query.Ciphertext = cipher
			//Send to all

			err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, query)
			if err != nil {
				return
			}
			//Start the key switch
			params := SwitchingParamters{
				PublicKey:  *query.PublicKey,
				Ciphertext: *query.Ciphertext,
			}
			s.SwitchingParameters <- params

			reply, err := s.switchKeys(tree, query.UUID)
			if err != nil {
				log.Error("Could not switch key : ", err)
			}
			log.Lvl1("Finished ciphertext switching. sending result to the querier ! ")
			//reply to the origin of the queries
			err = s.SendRaw(msg.ServerIdentity, reply)
			if err != nil {
				log.Error("Could not send reply to the server :", err)
			}
		} else {
			params := SwitchingParamters{
				PublicKey:  *query.PublicKey,
				Ciphertext: *query.Ciphertext,
			}
			s.SwitchingParameters <- params
		}
	} else {
		log.Error("Unknown message type :", msg.MsgType)
	}

}

//NewProtocol starts a new protocol given by the name in the treenodeinstance and returns it correctly initialized.
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tn.SetConfig(conf)
	if err != nil {
		return nil, err
	}
	var protocol onet.ProtocolInstance
	switch tn.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		protocol, err = s.newProtoCKG(tn)
		if err != nil {
			return nil, err
		}
	case protocols.CollectiveKeySwitchingProtocolName:
		protocol, err = s.newProtoCKS(tn)
		if err != nil {
			return nil, err
		}
	case protocols.CollectivePublicKeySwitchingProtocolName:
		protocol, err = s.newProtoCPKS(tn)
		if err != nil {
			return nil, err
		}
	case protocols.RelinearizationKeyProtocolName:
		protocol, err = s.newProtoRLK(tn)
		if err != nil {
			return nil, err
		}
	case protocols.RotationProtocolName:
		protocol, err = s.newProtoRotKG(tn)
	case protocols.CollectiveRefreshName:
		protocol, err = s.newProtoRefresh(tn)
		if err != nil {
			return nil, err
		}

	}

	return protocol, nil
}
