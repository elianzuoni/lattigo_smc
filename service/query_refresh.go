package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

//HandleRefreshQuery handler for queries for a refresh of a ciphertext
func (s *Service) HandleRefreshQuery(query *RefreshQuery) (network.Message, error) {
	log.Lvl1("Got request to refresh cipher : ", query.UUID)
	tree := s.Roster.GenerateBinaryTree()
	if query.Ciphertext == nil && query.InnerQuery {
		query.InnerQuery = false
		err := s.SendRaw(tree.Root.ServerIdentity, query)
		if err != nil {
			return nil, err
		}

	} else {
		err := s.refreshProto(query)
		if err != nil {
			log.Error("Could not start refresh ", err)
			return nil, err
		}
	}
	//this returns the id that was requested as the server will store it with the same id.
	return &ServiceState{query.UUID, true}, nil
}

func (s *Service) processRefreshQuery(msg *network.Envelope) {
	tmp := (msg.Msg).(*RefreshQuery)
	log.Lvl1("Got refresh query for cipher :", tmp.UUID)
	_, err := s.HandleRefreshQuery(tmp)
	if err != nil {
		log.Error("Could not do the refresh ", err)
	}
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
		log.Lvl1("Got params :)")
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
