package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/utils"
)

//Process a message from an other service. This is a big if-else-if loop over all type of messages that can be received.
func (s *Service) Process(msg *network.Envelope) {
	//Processor interface used to recognize messages between server
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		s.processSetupRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgStoreQuery) {
		s.processStoreQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyQuery) {
		s.processMultiplyQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		s.processMultiplyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumQuery) {
		s.processSumQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumReply) {
		s.processSumReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationQuery) {
		s.processRotationQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		s.processRotationReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRelinQuery) {
		s.processRelinQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRefreshQuery) {
		s.processRefreshQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgStoreReply) {
		s.processStoreReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		s.processKeyRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		s.processKeyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgReplyPlaintext) {
		s.processReplyPlaintext(msg)
	} else if msg.MsgType.Equal(msgTypes.msgQueryPlaintext) {
		s.processQueryPlaintext(msg)
	} else {
		log.Error("Unknown message type :", msg.MsgType)
	}

}

func (s *Service) processRefreshQuery(msg *network.Envelope) {
	tmp := (msg.Msg).(*RefreshQuery)
	log.Lvl1("Got refresh query for cipher :", tmp.UUID)
	_, err := s.HandleRefreshQuery(tmp)
	if err != nil {
		log.Error("Could not do the refresh ", err)
	}
}

func (s *Service) processReplyPlaintext(msg *network.Envelope) {
	tmp := (msg.Msg).(*ReplyPlaintext)
	log.Lvl1("Got a ciphertext switched with UUID : ", tmp.UUID)
	s.SwitchedCiphertext[tmp.UUID] = make(chan bfv.Ciphertext, 1)
	s.SwitchedCiphertext[tmp.UUID] <- *tmp.Ciphertext
}

func (s *Service) processStoreReply(msg *network.Envelope) {
	log.Lvl1("Got a store reply")
	tmp := (msg.Msg).(*StoreReply)
	log.Lvl1("ID Local , ", tmp.Local, "ID Remote: ", tmp.Remote, "Done :", tmp.Done)
	//Update the local values.
	s.LocalUUID[tmp.Local] = make(chan uuid.UUID, 1)
	s.LocalUUID[tmp.Local] <- tmp.Remote
	log.Lvl1("Updated value of the ciphertext. ")
}

func (s *Service) processRotationReply(msg *network.Envelope) {
	log.Lvl1("Got rotation replies")
	tmp := (msg.Msg).(*RotationReply)
	s.RotationReplies[tmp.Old] <- tmp.New
}

func (s *Service) processSumReply(msg *network.Envelope) {
	log.Lvl1("Got message for sum reply")
	tmp := (msg.Msg).(*SumReply)
	s.SumReplies[tmp.SumQuery] <- tmp.UUID
}

func (s *Service) processMultiplyReply(msg *network.Envelope) {
	tmp := (msg.Msg).(*MultiplyReply)
	log.Lvl1("Got reply of multiply query : ", tmp.UUID)
	s.MultiplyReplies[tmp.MultiplyQuery] <- tmp.UUID
}

func (s *Service) processKeyReply(msg *network.Envelope) {
	log.Lvl1("Got a key reply")
	tmp := (msg.Msg).(*KeyReply)
	if tmp.PublicKey != nil {
		s.MasterPublicKey = tmp.PublicKey
	}
	if tmp.EvaluationKey != nil {
		s.EvaluationKey = tmp.EvaluationKey
	}
	if tmp.RotationKeys != nil {
		s.RotationKey = tmp.RotationKeys
	}
	log.Lvl1("Got the public keys !")
}

func (s *Service) processQueryPlaintext(msg *network.Envelope) {
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
	return
}

func (s *Service) processKeyRequest(msg *network.Envelope) {
	log.Lvl1("Got a key request")
	reply := KeyReply{}
	tmp := (msg.Msg).(*KeyRequest)
	if tmp.PublicKey && s.pubKeyGenerated {
		reply.PublicKey = (s.MasterPublicKey)
	}
	if tmp.EvaluationKey && s.evalKeyGenerated {
		reply.EvaluationKey = s.EvaluationKey

	}
	if tmp.RotationKey && s.rotKeyGenerated {
		reply.RotationKeys = s.RotationKey
	}
	//Send the result.
	err := s.SendRaw(msg.ServerIdentity, &reply)
	if err != nil {
		log.Error("Could not send reply : ", err)
	}
}

func (s *Service) processRotationQuery(msg *network.Envelope) {
	log.Lvl1("Got request for rotation !")
	tmp := (msg.Msg).(*RotationQuery)
	rotIdx := tmp.RotIdx
	K := tmp.K
	id := tmp.UUID
	if !s.rotKeyGenerated {
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
		s.DataBase[newId] = eval.RotateRowsNew(cipher, s.RotationKey)
	case bfv.RotationLeft:
		s.DataBase[newId] = eval.RotateColumnsNew(cipher, K, s.RotationKey)
	case bfv.RotationRight:
		s.DataBase[newId] = eval.RotateColumnsNew(cipher, K, s.RotationKey)
	}
	reply := RotationReply{id, newId}
	err := s.SendRaw(msg.ServerIdentity, &reply)
	log.Lvl1("Sent result of rotaiton :) ")
	if err != nil {
		log.Error("Could not rotate ciphertext : ", err)
	}
	return
}

func (s *Service) processRelinQuery(msg *network.Envelope) {
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
}

func (s *Service) processSumQuery(msg *network.Envelope) {
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
	return
}

func (s *Service) processStoreQuery(msg *network.Envelope) {
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
}

func (s *Service) processSetupRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "got a setup message! (in process) ")
	tmp := (msg.Msg).(*SetupRequest)
	_, err := s.HandleSetupQuery(tmp)
	if err != nil {
		log.Error(err)
	}
}

func (s *Service) processMultiplyQuery(msg *network.Envelope) {
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
	return
}
