package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Handles the client's RotationQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (smc *Service) HandleRotationQuery(query *messages.RotationQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received RotationQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create request with its ID
	reqID := messages.NewRotationRequestID()
	req := &messages.RotationRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.RotationRepLock.Lock()
	s.RotationReplies[reqID] = make(chan *messages.RotationReply)
	s.RotationRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending RotationRequest to root:", query.CipherID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error("Couldn't send RotationRequest to root:", err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.RotationRepLock.RLock()
	replyChan := s.RotationReplies[reqID]
	s.RotationRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.RotationRepLock.Lock()
	close(replyChan)
	delete(s.RotationReplies, reqID)
	s.RotationRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	// Check validity
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform sum")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	}

	return &messages.RotationResponse{reply.NewCipherID, reply.Valid}, nil
}

// This method is executed at the root when receiving a RotationRequest.
// It checks for feasibility (whether or not it possesses the requested ciphertext) and, based on the result,
// it either returns an invalid reply, or performs the rotation and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
// TODO: it only check whether rotKeys is nil. If not, but the right rotation key was not generated, it panics.
func (smc *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RotationRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received RotationRequest for ciphertext", req.Query.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.RotationReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Check feasibility
	log.Lvl3(smc.ServerIdentity(), "Checking existence of ciphertext")
	ct, ok := s.GetCiphertext(req.Query.CipherID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	log.Lvl3(smc.ServerIdentity(), "Checking if rotation key was generated")
	// We don't need to hold the lock
	s.RotKeyLock.RLock()
	// The rotation key is modifiable, but it is the pointer s.rotationKey itself that changes, not its content
	rotKey := s.RotationKey
	s.RotKeyLock.RUnlock()
	if rotKey == nil {
		log.Error(smc.ServerIdentity(), "Rotation key not generated")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// TODO: refine check for specific rotation

	// Evaluate the rotation
	log.Lvl3(smc.ServerIdentity(), "Evaluating the rotation of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(req.Query.RotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, rotKey)
	// TODO: what? they are the same?
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, req.Query.K, rotKey)
	case bfv.RotationRight:
		ctRot = eval.RotateColumnsNew(ct, req.Query.K, rotKey)
	}

	// Register in local database
	idRot := messages.NewCipherID(smc.ServerIdentity())
	s.StoreCiphertext(idRot, ctRot)

	// Set fields in reply
	reply.NewCipherID = idRot
	reply.Valid = true

	// Send reply to server
	log.Lvl2(smc.ServerIdentity(), "Sending positive reply to server")
	err := smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RotationReply.
// It simply sends the reply through the channel.
func (smc *Service) processRotationReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RotationReply)

	log.Lvl1(smc.ServerIdentity(), "Received RotationReply:", reply.ReqID)

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(reply.SessionID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.RotationRepLock.RLock()
	s.RotationReplies[reply.ReqID] <- reply
	s.RotationRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
