// The goal of the Store Query is to store a new ciphertext into the system.

package session

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// HandleStoreQuery is the handler registered for message type StoreQuery.
// A client asks to store new (already encrypted) data into the system.
// The data is stored locally, and assigned a new CipherID indicating the owner.
func (service *Service) HandleStoreQuery(query *messages.StoreQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received StoreRequest query")

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	/*
		// Create SumRequest with its ID
		reqID := messages.NewStoreRequestID()
		req := &messages.StoreRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.storeRepLock.Lock()
		service.storeReplies[reqID] = make(chan *messages.StoreReply)
		service.storeRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending StoreRequest to the root")
		err := service.SendRaw(s.Root, req)
		if err != nil {
			err = errors.New("Couldn't send StoreRequest to the root: " + err.Error())
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
		service.storeRepLock.RLock()
		replyChan := service.storeReplies[reqID]
		service.storeRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.storeRepLock.Lock()
		close(replyChan)
		delete(service.storeReplies, reqID)
		service.storeRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel")

		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't store")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		}
		log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")

	*/

	// Store locally
	newID := s.StoreCiphertextNewID(query.Ciphertext)

	return &messages.StoreResponse{newID, true}, nil
}

/*
// StoreRequest is received at root from server.
// The ciphertext is stored under a fresh CipherID, which is returned in the reply.
func (service *Service) processStoreRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.StoreRequest)
	log.Lvl1(service.ServerIdentity(), "Root. Received forwarded request to store new ciphertext")

	// Start by declaring reply with minimal fields.
	reply := &messages.StoreReply{SessionID: req.SessionID, ReqID: req.ReqID, CipherID: messages.NilCipherID, Valid: false}

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := service.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Register in local database
	newCipherID := messages.NewCipherID(service.ServerIdentity())
	s.StoreCiphertext(newCipherID, req.Query.Ciphertext)

	// Set fields in reply
	reply.CipherID = newCipherID
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")
}

// This method is executed at the server when receiving the root's StoreReply.
// It simply sends the reply through the channel.
func (service *Service) processStoreReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.StoreReply)

	log.Lvl1(service.ServerIdentity(), "Received StoreReply:", reply.ReqID)

	// Simply send reply through channel
	service.storeRepLock.RLock()
	service.storeReplies[reply.ReqID] <- reply
	service.storeRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

*/
