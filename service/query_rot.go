// This file defines the behaviour when receiving a RotationQuery from client.
// HandleRotationQuery forwards the query to the root, and waits for a response on a channel.
// The root executes processRotationRequest, which, depending on whether or not it can retrieve the requested
// ciphertext, either stores the rotated ciphertext under a new CipherID and returns it to the server, or
// returns a value indicating the error.
// The root's reply is handled, at the server, by processRotationReply: depending on whether or not the reply indicates
// an error, it sends through the channel either the returned CipherID or a default nil value.
// When HandleRotationQuery wakes up, depending on what it received from the channel, it either returns (to the client)
// the new CipherID or an error.

package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// Handles the client's RotationQuery. Forwards the query to root, and waits for response on a channel.
// Either returns the new CipherID or a nil value, depending on what the root replied.
func (s *Service) HandleRotationQuery(query *RotationQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received RotationQuery for ciphertext:", query.ID)

	// Create request with its ID
	reqID := RotationRequestID(uuid.NewV1())
	req := RotationRequest{reqID, query}

	// Create channel before sending request to root.
	s.rotationReplies[reqID] = make(chan CipherID)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending RotationRequest to root:", query.ID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error("Couldn't send RotationRequest to root:", err)
		return nil, err
	}

	// Receive new CipherID from channel
	log.Lvl3(s.ServerIdentity(), "Sent RotationRequest to root. Waiting on channel to receive new CipherID...")
	newID := <-s.rotationReplies[reqID] // TODO: timeout if root cannot send reply
	// Check validity
	if newID == nilCipherID {
		err := errors.New("Received nilCipherID: root couldn't perform rotation")
		log.Error(s.ServerIdentity(), err)
		return nil, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid new CipherID from channel:", newID)
	// TODO: close channel?

	return &ServiceState{newID, false}, nil // TODO: what is pending?
}

// This method is executed at the root when receiving a RotationRequest.
// It checks for feasibility (whether or not it possesses the requested ciphertext) and, based on the result,
// it either returns an invalid reply, or performs the rotation and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
func (s *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RotationRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received RotationRequest for ciphertext", req.ID)

	// Check feasibility
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertext")
	ct, ok := s.database[req.ID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.ID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity,
			&RotationReply{req.RotationRequestID, nilCipherID, nilCipherID, false})
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
	idRot := CipherID(uuid.NewV1())
	s.database[idRot] = ctRot

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity,
		&RotationReply{req.RotationRequestID, req.ID, idRot, true})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RotationReply.
// Based on whether or not the reply is valid, it either sends through the channel the new CipherID
// or nilCipherID.
func (s *Service) processRotationReply(msg *network.Envelope) {
	rep := (msg.Msg).(*RotationReply)

	log.Lvl1(s.ServerIdentity(), "Received RotationReply")

	// Check validity
	if !rep.valid {
		log.Error(s.ServerIdentity(), "The received RotationReply is invalid")
		s.rotationReplies[rep.RotationRequestID] <- nilCipherID
		return
	}

	log.Lvl3(s.ServerIdentity(), "The received RotationReply is valid. Sending through channel")
	s.rotationReplies[rep.RotationRequestID] <- rep.New
	log.Lvl4(s.ServerIdentity(), "Sent new CipherID through channel")

	return
}
