package services

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
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
	log.Lvl1("Got request to refresh cipher : ", query.UUID)
	tree := s.Roster.GenerateBinaryTree()
	if query.Ciphertext == nil {
		err := s.SendRaw(tree.Root.ServerIdentity, query)
		if err != nil {
			return nil, err
		}

	}
	//this returns the id that was requested as the server will store it with the same id.
	return &ServiceState{query.UUID, true}, nil
}

func (s *Service) refreshProto(query *RefreshQuery) error {
	tree := s.GenerateBinaryTree()
	if tree.Root.ServerIdentity.Equal(s.ServerIdentity()) {
		cipher, ok := s.DataBase[query.UUID]
		if !ok {
			log.Error("Ciphertext non existent", query.UUID)
			return errors.New("cipher does not exist")

		}

		query.Ciphertext = cipher
		err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, query)
		if err != nil {
			return err
		}

		//Start the protocol
		log.Lvl1(s.ServerIdentity(), "Starting collective key refresh ")
		s.RefreshParams <- query.Ciphertext
		tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveRefreshName)
		protocol, err := s.NewProtocol(tni, nil)
		if err != nil {
			panic(err)
		}
		err = s.RegisterProtocolInstance(protocol)
		if err != nil {
			log.ErrFatal(err, "Could not register protocol instance")
		}

		refresh := protocol.(*protocols.RefreshProtocol)

		<-time.After(1 * time.Second) //wait for other parties to have the parameters.

		err = refresh.Start()
		if err != nil {
			log.ErrFatal(err, "Could not start collective key generation protocol")
		}
		go refresh.Dispatch()

		refresh.Wait()
		s.DataBase[query.UUID] = &refresh.Ciphertext
	} else {
		if query.Ciphertext != nil {
			//put it in the channel
			s.RefreshParams <- query.Ciphertext
		}
	}

	return nil
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

func (s *Service) HandleRotationQuery(query *RotationQuery) (network.Message, error) {
	log.Lvl1("Got rotation request : ", query.UUID)
	tree := s.Roster.GenerateBinaryTree()
	if !s.rotKeyGenerated[query.RotIdx] {
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
