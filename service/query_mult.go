// This file defines the behaviour when receiving a MultiplyQuery from client.
// HandleMultiplyQuery forwards the query to the root, and waits for a response on a channel.
// The root executes processMultiplyRequest, which, depending on whether or not it can retrieve the requested
// ciphertexts, either stores the product-ciphertext under a new CipherID and returns it to the server, or
// a value indicating the error.
// The root's reply is handled, at the server, by processMultiplyReply: depending on whether or not the reply indicates
// an error, it sends through the channel either the returned CipherID or a default nil value.
// When HandleMultiplyQuery wakes up, depending on what it received from the channel, it either returns (to the client)
// the new CipherID or an error.

package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// Handles the client's MultiplyQuery. Forwards the query to root, and waits for response on a channel.
// Either returns the new CipherID or a nil value, depending on what the root replied.
func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received MultiplyQuery:", query.ID1, "*", query.ID2)

	// Create MultiplyRequest with its ID
	reqID := MultiplyRequestID(uuid.NewV1())
	req := MultiplyRequest{reqID, query}

	// Create channel before sending request to root.
	s.multiplyReplies[reqID] = make(chan CipherID)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending MulitplyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send MultiplyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive new CipherID from channel
	log.Lvl3(s.ServerIdentity(), "Sent MultiplyRequest to root. Waiting on channel to receive new CipherID...")
	newID := <-s.multiplyReplies[reqID] // TODO: timeout if root cannot send reply
	if newID == nilCipherID {
		err := errors.New("Received nilCipherID: root couldn't perform multiplication")
		log.Error(s.ServerIdentity(), err)
		return nil, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid new CipherID from channel:", newID)
	// TODO: close channel?

	return &ServiceState{newID, false}, nil // TODO: what is pending?
}

// This method is executed at the root when receiving a MultiplyRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the multiplication and stores the new
// ciphertext under a new CipherID which is returned in a valid reply.
func (s *Service) processMultiplyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*MultiplyRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received MultiplyRequest ", req.MultiplyRequestID,
		"for product:", req.ID1, "*", req.ID2)

	// Check feasibilty
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertexts")
	ct1, ok := s.database[req.ID1]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.ID1, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity,
			&MultiplyReply{req.MultiplyRequestID, nilCipherID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	ct2, ok := s.database[req.ID2]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.ID2, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity,
			&MultiplyReply{req.MultiplyRequestID, nilCipherID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Evaluate multiplication
	log.Lvl3(s.ServerIdentity(), "Evaluating multiplication of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ct := eval.MulNew(ct1, ct2)

	// Register in local database
	id := CipherID(uuid.NewV1())
	s.database[id] = ct

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity, &MultiplyReply{req.MultiplyRequestID, id, true})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's MultiplyReply.
// Based on whether or not the reply is valid, it either sends through the channel the new CipherID
// or nilCipherID.
func (s *Service) processMultiplyReply(msg *network.Envelope) {
	rep := (msg.Msg).(*MultiplyReply)

	log.Lvl1(s.ServerIdentity(), "Received MultiplyReply:", rep.MultiplyRequestID)

	// Check validity
	if !rep.valid {
		log.Error(s.ServerIdentity(), "The received MultiplyReply is invalid")
		s.multiplyReplies[rep.MultiplyRequestID] <- nilCipherID
		return
	}

	log.Lvl3(s.ServerIdentity(), "The received MultiplyReply is valid. Sending through channel")
	s.multiplyReplies[rep.MultiplyRequestID] <- rep.NewID
	log.Lvl4(s.ServerIdentity(), "Sent new CipherID through channel")

	return
}
