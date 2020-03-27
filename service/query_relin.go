package service

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

//HandleRelinearizationQuery query for a ciphertext to be relinearized.
func (s *Service) HandleRelinearizationQuery(query *RelinQuery) (network.Message, error) {
	log.Lvl1("Got request to relinearize: ", query.UUID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, query)
	if err != nil {
		return nil, err
	}

	//this returns the id that was requested as the server will store it with the same id.
	return &ServiceState{query.UUID, false}, nil

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
