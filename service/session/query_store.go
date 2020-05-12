// The goal of the Store Query is to store a new ciphertext into the system.

package session

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleStoreQuery(query *messages.StoreQuery) (network.Message, error) {
	log.Lvl2(service.ServerIdentity(), "Received StoreRequest query")

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Store locally
	newID := s.StoreCiphertextNewID(query.Ciphertext)
	// Store ID under name
	s.StoreCipherID(query.Name, newID)

	return &messages.StoreResponse{newID, true}, nil
}
