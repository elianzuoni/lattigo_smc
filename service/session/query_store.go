package session

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleStoreQuery(query *messages.StoreQuery) (network.Message, error) {
	log.Lvl2(service.ServerIdentity(), "Received StoreAndNameQuery")

	// Extract Session, if existent
	s, ok := service.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Store locally
	newID := s.StoreCiphertextNewID(query.Ciphertext)

	return &messages.StoreResponse{newID, true}, nil
}
