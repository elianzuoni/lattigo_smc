// The goal of the Store Query is to store a new ciphertext into the system. The root decides its CipherID.

package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// HandleStoreQuery is the handler registered for message type StoreQuery:
// a client asks to store new data into the system.
// The server forwards the request to the root, which stores the ciphertext and assigns it a CipherID which is returned
// in the reply.
func (smc *Service) HandleStoreQuery(query *StoreQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received StoreRequest query")

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[query.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create SumRequest with its ID
	reqID := newStoreRequestID()
	req := &StoreRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.storeRepLock.Lock()
	s.storeReplies[reqID] = make(chan *StoreReply)
	s.storeRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending StoreRequest to the root")
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send StoreRequest to the root: " + err.Error())
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.storeRepLock.RLock()
	replyChan := s.storeReplies[reqID]
	s.storeRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.storeRepLock.Lock()
	close(replyChan)
	delete(s.storeReplies, reqID)
	s.storeRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't store")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")

	return &StoreResponse{reply.CipherID, reply.Valid}, nil
}

// StoreRequest is received at root from server.
// The ciphertext is stored under a fresh CipherID, which is returned in the reply.
func (smc *Service) processStoreRequest(msg *network.Envelope) {
	req := (msg.Msg).(*StoreRequest)
	log.Lvl1(smc.ServerIdentity(), "Root. Received forwarded request to store new ciphertext")

	// Start by declaring reply with minimal fields.
	reply := &StoreReply{SessionID: req.SessionID, ReqID: req.ReqID, CipherID: NilCipherID, Valid: false}

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[req.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Register in local database
	newCipherID := newCipherID(smc.ServerIdentity())
	s.databaseLock.Lock()
	s.database[newCipherID] = req.Query.Ciphertext
	s.databaseLock.Unlock()

	// Set fields in reply
	reply.CipherID = newCipherID
	reply.Valid = true

	// Send reply to server
	log.Lvl2(smc.ServerIdentity(), "Sending positive reply to server")
	err := smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")
}

// This method is executed at the server when receiving the root's StoreReply.
// It simply sends the reply through the channel.
func (smc *Service) processStoreReply(msg *network.Envelope) {
	reply := (msg.Msg).(*StoreReply)

	log.Lvl1(smc.ServerIdentity(), "Received StoreReply:", reply.ReqID)

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[reply.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.storeRepLock.RLock()
	s.storeReplies[reply.ReqID] <- reply
	s.storeRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
