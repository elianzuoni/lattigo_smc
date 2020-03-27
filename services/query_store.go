package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/utils"
	"time"
)

// HandleStoreQuery is the handler registered for message type QueryData: a client asks to store new data into the system.
// After some checks, the data is encrypted (TODO: WTF???) and associated to a fresh UUID: both are sent in a StoreQuery
// to the root. The root will store the ciphertext in its database under a new fresh UUID (TODO: why?),
// which it will send back to this server. This server handles this response in the processStoreReply method, which
// puts the remote UUID in a channel. This method waits on that channel for confirmation, then returns the remote UUID
// to the client (the original one is only used to index the channel on which to listen).
func (s *Service) HandleStoreQuery(query *QueryData) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received SendData query")

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
			Id:      uuid.UUID{},
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
	// Generate a fresh UUID for this ciphertext.
	id := uuid.NewV1()

	// Send the StoreQuery to the root.
	log.Lvl2(s.ServerIdentity(), "Sending StoreQuery to the root")
	err = s.SendRaw(tree.Root.ServerIdentity, &StoreQuery{cipher, id})
	if err != nil {
		log.Error(s.ServerIdentity(), "Couldn't send StoreQuery to the root:", err) // TODO: why not return nil, err?
	}

	// Wait to receive confirmation from root (it will be processed by processStoreReply and put in the channel)
	log.Lvl2(s.ServerIdentity(), "Waiting to receive remoteID as confirmation from root")
	for {
		select {
		case remoteID := <-s.LocalUUID[id]: // TODO: how do we know it is already defined?
			log.Lvl2(s.ServerIdentity(), "Received confirmation from root")
			return &ServiceState{remoteID, true}, nil // TODO: why Pending = true?

		case <-time.After(1 * time.Second):
			log.Lvl4(s.ServerIdentity(), "Elapsed 1 second waiting for confirmation. ")
			break
		}
	}

}

// StoreQuery is received at root from server.
// The ciphertext is stored under a fresh UUID, which is returned, as confirmation, along with the original UUID.
func (s *Service) processStoreQuery(msg *network.Envelope) {
	query := (msg.Msg).(*StoreQuery)
	id := uuid.NewV1()
	log.Lvl1(s.ServerIdentity(), "Root. Received forwarded request to store new ciphertext wth ID:", query.UUID)

	// Store ciphertext under fresh UUID
	s.DataBase[id] = query.Ciphertext
	log.Lvl4(s.ServerIdentity(), "Original UUID:", query.UUID, "; Fresh UUID:", id)

	// Send new and original UUIDs in acknowledgement
	sender := msg.ServerIdentity
	ack := StoreReply{query.UUID, id, true}
	log.Lvl2(s.ServerIdentity(), "Sending ack to server", sender)
	err := s.SendRaw(sender, &ack)
	if err != nil {
		log.Error(s.ServerIdentity(), "Couldn't send ack to server", sender)
	}
	log.Lvl2(s.ServerIdentity(), "Sent ack to server", sender)
}

// StoreReply is received at server from root.
// When this method is executed, the method HandleStoreQuery is waiting on the channel for the remote UUID,
// so we just send it and awake the goroutine executing that method.
func (s *Service) processStoreReply(msg *network.Envelope) {
	reply := (msg.Msg).(*StoreReply)
	log.Lvl1(s.ServerIdentity(), "Server. Received StoreReply. LocalID:", reply.Local, "RemoteID:", reply.Remote)

	// Send the RemoteID through the channel
	log.Lvl2(s.ServerIdentity(), "Sending RemoteID", reply.Remote, "through channel")
	s.LocalUUID[reply.Local] = make(chan uuid.UUID, 1) // TODO: shouldn't this be initialised in HandleStoreQuery?
	s.LocalUUID[reply.Local] <- reply.Remote

	log.Lvl3(s.ServerIdentity(), "Sent RemoteID", reply.Remote, "through channel")
}
