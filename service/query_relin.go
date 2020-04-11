package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's RelinQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns a valid or an invalid response, depending on what the root replied.
func (smc *Service) HandleRelinearisationQuery(query *RelinQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Server. Received RelinQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create RelinRequest with its ID
	reqID := newRelinRequestID()
	req := &RelinRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.relinRepLock.Lock()
	s.relinReplies[reqID] = make(chan *RelinReply)
	s.relinRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending RelinRequest to root.")
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Couldn't send RelinRequest to root: ", err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.relinRepLock.RLock()
	replyChan := s.relinReplies[reqID]
	s.relinRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.relinRepLock.Lock()
	close(replyChan)
	delete(s.relinReplies, reqID)
	s.relinRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform relinearisation")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	}

	return &RelinResponse{reply.NewCipherID, reply.Valid}, nil

}

// This method is executed at the root when receiving a SumRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the relinearisation and stores the new ciphertext
// under the same CipherID as before and returns a valid reply.
func (smc *Service) processRelinRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RelinRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received RelinRequest for ciphertext", req.Query.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &RelinReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Check existence of ciphertext
	log.Lvl3(smc.ServerIdentity(), "Checking existence of ciphertext")
	s.databaseLock.RLock()
	ct, ok := s.database[req.Query.CipherID]
	s.databaseLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested ciphertext does not exist:", req.Query.CipherID)
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// Check existence of evaluation key
	log.Lvl3(smc.ServerIdentity(), "Checking existence of evaluation key")
	// We don't need to hold the lock until the end.
	s.evalKeyLock.RLock()
	evalKey := s.evalKey // We can do this, since s.evalKey is unmodifiable.
	s.evalKeyLock.RUnlock()
	if evalKey == nil {
		log.Error(smc.ServerIdentity(), "Evaluation key not generated")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// Check that the ciphertext has the correct degree
	log.Lvl3(smc.ServerIdentity(), "Checking degree of ciphertext (cannot relinearise with degree >= 3)")
	if ct.Degree() >= 3 {
		log.Error(smc.ServerIdentity(), "Cannot relinearise ciphertext of degree >= 3")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Relinearise
	log.Lvl3(smc.ServerIdentity(), "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, evalKey)

	// Register in local database
	newCipherID := newCipherID(smc.ServerIdentity())
	s.databaseLock.Lock()
	s.database[newCipherID] = ctRelin
	s.databaseLock.Unlock()

	// Set fields in reply
	reply.Valid = true
	reply.NewCipherID = newCipherID

	// Send reply to server
	log.Lvl2(smc.ServerIdentity(), "Sending positive reply to server")
	err := smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RelinReply.
// It simply sends the reply through the channel.
func (smc *Service) processRelinReply(msg *network.Envelope) {
	reply := (msg.Msg).(*RelinReply)

	log.Lvl1(smc.ServerIdentity(), "Received RelinReply:", reply.ReqID)

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.relinRepLock.RLock()
	s.relinReplies[reply.ReqID] <- reply
	s.relinRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
