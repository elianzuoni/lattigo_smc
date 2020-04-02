package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's MultiplyQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (s *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received MultiplyQuery:", query.CipherID1, "*", query.CipherID2)

	// Create MultiplyRequest with its ID
	reqID := newMultiplyRequestID()
	req := MultiplyRequest{reqID, query}

	// Create channel before sending request to root.
	s.multiplyReplies[reqID] = make(chan *MultiplyReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending MulitplyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send MultiplyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent MultiplyRequest to root. Waiting on channel to receive reply...")
	reply := <-s.multiplyReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform multiplication")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(s.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)
	}
	// TODO: close channel?

	return &MultiplyResponse{reply.NewCipherID, reply.Valid}, nil
}

// This method is executed at the root when receiving a MultiplyRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the multiplication and stores the new
// ciphertext under a new CipherID which is returned in a valid reply.
func (s *Service) processMultiplyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*MultiplyRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received MultiplyRequest ", req.ReqID,
		"for product:", req.Query.CipherID1, "*", req.Query.CipherID2)

	// Check feasibilty
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertexts")
	ct1, ok := s.database[req.Query.CipherID1]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.Query.CipherID1, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity,
			&MultiplyReply{req.ReqID, NilCipherID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	ct2, ok := s.database[req.Query.CipherID2]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.Query.CipherID2, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity,
			&MultiplyReply{req.ReqID, NilCipherID, false})
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
	newCipherID := newCipherID()
	s.database[newCipherID] = ct

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity,
		&MultiplyReply{req.ReqID, newCipherID, true})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's MultiplyReply.
// It simply sends the reply through the channel.
func (s *Service) processMultiplyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*MultiplyReply)

	log.Lvl1(s.ServerIdentity(), "Received MultiplyReply:", reply.ReqID)

	// Simply send reply through channel
	s.multiplyReplies[reply.ReqID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
