package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service/circuit/tree"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/session"
	"sync"
)

type Circuit struct {
	CircuitID messages.CircuitID

	service *Service
	session *session.Session

	Description   string
	OperationTree *tree.OperationTree

	// Stores the name-CipherID correspondence
	cipherIDsLock sync.RWMutex
	cipherIDs     map[string]messages.CipherID
}

type CircuitStore struct {
	// Useful to launch requests from the Circuit object
	service *Service

	circuitsLock sync.RWMutex
	circuits     map[messages.CircuitID]*Circuit
}

// Constructor of CircuitStore
func NewCircuitStore(serv *Service) *CircuitStore {
	log.Lvl2("Creating new CircuitStore")

	return &CircuitStore{
		service: serv,

		circuitsLock: sync.RWMutex{},
		circuits:     make(map[messages.CircuitID]*Circuit),
	}
}

// Constructor of Circuit.
func (store *CircuitStore) NewCircuit(id messages.CircuitID, sessionID messages.SessionID, desc string) {
	log.Lvl2("Circuit constructor started")

	// Extract Session, if existent
	sess, ok := store.service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(store.service.ServerIdentity(), err)
		return
	}

	circuit := &Circuit{
		CircuitID: id,

		service: store.service,
		session: sess,

		// No need to initialise cipherIDsLock
		cipherIDs: make(map[string]messages.CipherID),
	}

	circuit.Description = desc
	// Here if interested in replicating the OperationTree at all nodes, we should parse the Description

	// Store new session
	store.circuitsLock.Lock()
	store.circuits[id] = circuit
	store.circuitsLock.Unlock()

	return
}

// Method to retrieve Circuit. Returns boolean indicating success
func (store *CircuitStore) GetCircuit(id messages.CircuitID) (c *Circuit, ok bool) {
	store.circuitsLock.RLock()
	c, ok = store.circuits[id]
	store.circuitsLock.RUnlock()

	return
}

// Method to delete Circuit from CircuitStore. Does nothing if session does not exist.
func (store *CircuitStore) DeleteCircuit(id messages.CircuitID) {
	log.Lvl2("Deleting circuit")

	store.circuitsLock.Lock()
	delete(store.circuits, id)
	store.circuitsLock.Unlock()

	return
}
