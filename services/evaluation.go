package services

import (
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

//HandleRefreshQuery handler for queries for a refresh of a ciphertext
func (s *Service) HandleRefreshQuery(query *RefreshQuery) (network.Message, error) {
	return nil, nil
}

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
