package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

//HandleRotationQuery handles a query for a rotation. Return the id of the rotated ciphertext.
func (s *Service) HandleRotationQuery(query *RotationQuery) (network.Message, error) {
	log.Lvl1("Got rotation request : ", query.UUID)
	tree := s.Roster.GenerateBinaryTree()
	if !s.rotKeyGenerated {
		log.Lvl1("Key has not been generated ! ")
		return &ServiceState{uuid.UUID{}, false}, nil
	}
	err := s.SendRaw(tree.Root.ServerIdentity, query)
	if err != nil {
		return nil, err
	}

	s.RotationReplies[query.UUID] = make(chan uuid.UUID)
	res := <-s.RotationReplies[query.UUID]

	return &ServiceState{res, false}, nil

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

func (s *Service) processRotationReply(msg *network.Envelope) {
	log.Lvl1("Got rotation replies")
	tmp := (msg.Msg).(*RotationReply)
	s.RotationReplies[tmp.Old] <- tmp.New
}
