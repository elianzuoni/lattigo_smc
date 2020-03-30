package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's RotationQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (s *Service) HandleRotationQuery(query *RotationQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received RotationQuery for ciphertext:", query.CipherID)

	// Create request with its ID
	reqID := newRotationRequestID()
	req := RotationRequest{reqID, query}

	// Create channel before sending request to root.
	s.rotationReplies[reqID] = make(chan *RotationReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending RotationRequest to root:", query.CipherID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error("Couldn't send RotationRequest to root:", err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent RotationRequest to root. Waiting on channel to receive new CipherID...")
	reply := <-s.rotationReplies[reqID] // TODO: timeout if root cannot send reply
	// Check validity
	if !reply.valid {
		err := errors.New("Received invalid reply: root couldn't perform sum")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(s.ServerIdentity(), "Received valid reply from channel")
	}
	// TODO: close channel?

	return &RotationResponse{reply.Old, reply.New, reply.valid}, nil
}

// This method is executed at the root when receiving a RotationRequest.
// It checks for feasibility (whether or not it possesses the requested ciphertext) and, based on the result,
// it either returns an invalid reply, or performs the rotation and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
func (s *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RotationRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received RotationRequest for ciphertext", req.CipherID)

	// Check feasibility
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertext")
	ct, ok := s.database[req.CipherID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.CipherID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity,
			&RotationReply{req.RotationRequestID, NilCipherID, NilCipherID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	log.Lvl3(s.ServerIdentity(), "Checking if rotation key was generated")
	if !s.rotKeyGenerated {
		log.Error(s.ServerIdentity(), "Rotation key not generated")
		return
	}

	// Evaluate the rotation
	log.Lvl3(s.ServerIdentity(), "Evaluating the rotation of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(req.RotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, s.rotationKey)
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, req.K, s.rotationKey)
	case bfv.RotationRight:
		ctRot = eval.RotateColumnsNew(ct, req.K, s.rotationKey)
	}

	// Register in local database
	idRot := newCipherID()
	s.database[idRot] = ctRot

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity,
		&RotationReply{req.RotationRequestID, req.CipherID, idRot, true})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RotationReply.
// It simply sends the reply through the channel.
func (s *Service) processRotationReply(msg *network.Envelope) {
	reply := (msg.Msg).(*RotationReply)

	log.Lvl1(s.ServerIdentity(), "Received RotationReply:", reply.RotationRequestID)

	// Simply send reply through channel
	s.rotationReplies[reply.RotationRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
