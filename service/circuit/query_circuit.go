package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/circuit/tree"
	"lattigo-smc/service/messages"
)

// Handler for reception of CircuitQuery from client.
func (service *Service) HandleCircuitQuery(query *messages.CircuitQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received CircuitQuery")

	// Parse circuit description
	log.Lvl3(service.ServerIdentity(), "Going to parse circuit description")
	t := tree.NewBinaryTree(service.treeSupplier(query.SessionID), service.treeAdder(query.SessionID),
		service.treeMultiplier(query.SessionID), service.treeRotator(query.SessionID))
	err := t.ParseFromRPN(query.Desc)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not parse circuit description:", err)
		return nil, err
	}

	// Launch evaluation and get result
	resID := t.Evaluate()
	if resID == messages.NilCipherID {
		err = errors.New("Evaluation returned invalid result")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	log.Lvl3(service.ServerIdentity(), "Got the result!")

	// Switch the result under the provided public key
	result, err := service.DelegateSwitchCipher(query.SessionID, resID, query.PublicKey)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not switch the result:", err)
		return nil, err
	}

	return &messages.CircuitResponse{result, true}, nil
}

// Adapts the DelegateSumCiphers method to the signature needed by the Tree constructor
func (service *Service) treeAdder(sessionID messages.SessionID) tree.BinaryOperation {
	return func(cipherID1 messages.CipherID, cipherID2 messages.CipherID) (messages.CipherID, error) {
		return service.DelegateSumCiphers(sessionID, cipherID1, cipherID2)
	}
}

// Adapts the DelegateMultiplyCiphers method to the signature needed by the Tree constructor
func (service *Service) treeMultiplier(sessionID messages.SessionID) tree.BinaryOperation {
	return func(cipherID1 messages.CipherID, cipherID2 messages.CipherID) (messages.CipherID, error) {
		return service.DelegateMultiplyCiphers(sessionID, cipherID1, cipherID2, true)
	}
}

// Adapts the DelegateRotateCipher method to the signature needed by the Tree constructor
func (service *Service) treeRotator(sessionID messages.SessionID) tree.RotOperation {
	return func(cipherID messages.CipherID, rotIdx int, k uint64) (messages.CipherID, error) {
		return service.DelegateRotateCipher(sessionID, cipherID, rotIdx, k)
	}
}

// Adapts the GetCipherID method to the signature needed by the Tree constructor
func (service *Service) treeSupplier(sessionID messages.SessionID) tree.Supplier {
	return func(fullName string) (messages.CipherID, error) {
		log.Lvl2(service.ServerIdentity(), "Resolving name:", fullName)

		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(sessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return messages.NilCipherID, err
		}

		id, ok := s.GetCipherID(fullName)
		if !ok {
			err := errors.New("Requested name could not be resolved")
			log.Error(service.ServerIdentity(), err)
			return messages.NilCipherID, err
		}

		return id, nil
	}
}
