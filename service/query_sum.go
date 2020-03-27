package service

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

//HandleSumQuery the client handler for queries of sum of two ciphertext
//Return the ID of the result of the operation
func (s *Service) HandleSumQuery(sumQuery *SumQuery) (network.Message, error) {
	log.Lvl1("Got request to sum up two ciphertext : ", sumQuery.UUID, "+", sumQuery.Other)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, sumQuery)
	if err != nil {
		return nil, err
	}

	s.SumReplies[*sumQuery] = make(chan uuid.UUID)
	id := <-s.SumReplies[*sumQuery]

	return &ServiceState{id, false}, nil
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

func (s *Service) processSumReply(msg *network.Envelope) {
	log.Lvl1("Got message for sum reply")
	tmp := (msg.Msg).(*SumReply)
	s.SumReplies[tmp.SumQuery] <- tmp.UUID
}
