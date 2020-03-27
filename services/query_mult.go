package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

//HandleMultiplyQuery handler for queries of multiply of two ciphertext
//Return the ID of the result of the operation
func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	log.Lvl1("Got request to multiply two ciphertext : ", query.UUID, "+", query.Other)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, query)
	if err != nil {
		return nil, err
	}

	s.MultiplyReplies[*query] = make(chan uuid.UUID)
	id := <-s.MultiplyReplies[*query]

	return &ServiceState{id, false}, nil

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

func (s *Service) processMultiplyReply(msg *network.Envelope) {
	tmp := (msg.Msg).(*MultiplyReply)
	log.Lvl1("Got reply of multiply query : ", tmp.UUID)
	s.MultiplyReplies[tmp.MultiplyQuery] <- tmp.UUID
}
