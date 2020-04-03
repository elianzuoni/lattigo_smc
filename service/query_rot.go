package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's RotationQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (smc *Service) HandleRotationQuery(query *RotationQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received RotationQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create request with its ID
	reqID := newRotationRequestID()
	req := RotationRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.rotationReplies[reqID] = make(chan *RotationReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending RotationRequest to root:", query.CipherID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error("Couldn't send RotationRequest to root:", err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Sent RotationRequest to root. Waiting on channel to receive new CipherID...")
	reply := <-s.rotationReplies[reqID] // TODO: timeout if root cannot send reply
	// Check validity
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform sum")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	}
	// TODO: close channel?

	return &RotationResponse{reply.NewCipherID, reply.Valid}, nil
}

// This method is executed at the root when receiving a RotationRequest.
// It checks for feasibility (whether or not it possesses the requested ciphertext) and, based on the result,
// it either returns an invalid reply, or performs the rotation and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
func (smc *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RotationRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received RotationRequest for ciphertext", req.Query.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &RotationReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: NilCipherID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Check feasibility
	log.Lvl3(smc.ServerIdentity(), "Checking existence of ciphertext")
	ct, ok := s.database[req.Query.CipherID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	log.Lvl3(smc.ServerIdentity(), "Checking if rotation key was generated")
	if !s.rotKeyGenerated {
		log.Error(smc.ServerIdentity(), "Rotation key not generated")
		return
	}

	// Evaluate the rotation
	log.Lvl3(smc.ServerIdentity(), "Evaluating the rotation of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(req.Query.RotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, s.rotationKey)
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, req.Query.K, s.rotationKey)
	case bfv.RotationRight:
		ctRot = eval.RotateColumnsNew(ct, req.Query.K, s.rotationKey)
	}

	// Register in local database
	idRot := newCipherID()
	s.database[idRot] = ctRot

	// Send reply to server
	reply.NewCipherID = idRot
	reply.Valid = true
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
	reply := (msg.Msg).(*RotationReply)

	log.Lvl1(smc.ServerIdentity(), "Received RotationReply:", reply.ReqID)

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.rotationReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
