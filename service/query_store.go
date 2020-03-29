// This file defines the behaviour of the service when a StoreRequest is received.
// HandleStoreQuery is charged with handling the client query: the query contains a clear-text vector, which
// is encrypted and sent to the root, alongside an ID.
// processStoreRequest is the method - executed at the root - charged with dealing with the StoreRequest received
// from the server: it stores the ciphertext in the local database under the received ID.
// No protocol is fired while handling this query.

package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/utils"
)

// HandleStoreQuery is the handler registered for message type StoreQuery: a client asks to store new data into the system.
// After some checks, the data is encrypted (TODO: WTF???) and associated to an ID: both are sent in a StoreRequest
// to the root. The root will store the ciphertext in its database under the provided ID.
func (s *Service) HandleStoreQuery(query *StoreQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received StoreRequest query")

	data := query.Data
	tree := query.Roster.GenerateBinaryTree()

	// Check if the requested operation can be performed.
	log.Lvl3(s.ServerIdentity(), "Checking existence of MasterPublicKey")
	if !s.pubKeyGenerated {
		//here we can not yet do the answer
		return nil, errors.New("Key has not yet been generated.")
	}
	if s.MasterPublicKey == nil {
		log.Error(s.ServerIdentity(), "Master public key not available")
		// TODO: what do we return here?
		return &ServiceState{
			Id:      CipherID{},
			Pending: true,
		}, nil
	}

	// Encrypt the received data (TODO: why?).
	log.Lvl3(s.ServerIdentity(), "Encrypting received data")
	encoder := bfv.NewEncoder(s.Params)
	coeffs, err := utils.BytesToUint64(data, true)
	if err != nil {
		return nil, err
	}
	pt := bfv.NewPlaintext(s.Params)
	encoder.EncodeUint(coeffs, pt)
	encryptorPk := bfv.NewEncryptorFromPk(s.Params, s.MasterPublicKey)
	cipher := encryptorPk.EncryptNew(pt)
	// Generate a fresh ID1 for this ciphertext.
	id := CipherID(uuid.NewV1())

	// Send the StoreRequest to the root.
	log.Lvl2(s.ServerIdentity(), "Sending StoreRequest to the root")
	err = s.SendRaw(tree.Root.ServerIdentity, &StoreRequest{cipher, id})
	if err != nil {
		err = errors.New("Couldn't send StoreRequest to the root: " + err.Error())
		log.Error(s.ServerIdentity(), err)
		return nil, err
	}

	return &ServiceState{
		Id:      id,
		Pending: true,
	}, nil
}

// StoreRequest is received at root from server.
// The ciphertext is stored under the provided ID.
func (s *Service) processStoreRequest(msg *network.Envelope) {
	query := (msg.Msg).(*StoreRequest)
	log.Lvl1(s.ServerIdentity(), "Root. Received forwarded request to store new ciphertext with ID:", query.ID)

	// Store ciphertext under fresh ID1
	s.database[query.ID] = query.Ciphertext
}
