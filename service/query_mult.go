package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's MultiplyQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (smc *Service) HandleMultiplyQuery(query *MultiplyQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received MultiplyQuery:", query.CipherID1, "*", query.CipherID2)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create MultiplyRequest with its ID
	reqID := newMultiplyRequestID()
	req := MultiplyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.multiplyReplies[reqID] = make(chan *MultiplyReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending MulitplyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send MultiplyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Sent MultiplyRequest to root. Waiting on channel to receive reply...")
	reply := <-s.multiplyReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform multiplication")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)
	}
	// TODO: close channel?

	return &MultiplyResponse{reply.NewCipherID, reply.Valid}, nil
}

// This method is executed at the root when receiving a MultiplyRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the multiplication and stores the new
// ciphertext under a new CipherID which is returned in a valid reply.
func (smc *Service) processMultiplyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*MultiplyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received MultiplyRequest ", req.ReqID,
		"for product:", req.Query.CipherID1, "*", req.Query.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &MultiplyReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: NilCipherID, Valid: false}

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

	// Check feasibilty
	log.Lvl3(smc.ServerIdentity(), "Checking existence of ciphertexts")
	ct1, ok := s.database[req.Query.CipherID1]
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID1, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	ct2, ok := s.database[req.Query.CipherID2]
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID2, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Evaluate multiplication
	log.Lvl3(smc.ServerIdentity(), "Evaluating multiplication of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ct := eval.MulNew(ct1, ct2)

	// Register in local database
	newCipherID := newCipherID()
	s.database[newCipherID] = ct

	// Send reply to server
	reply.NewCipherID = newCipherID
	reply.Valid = true
	log.Lvl2(smc.ServerIdentity(), "Sending positive reply to server")
	err := smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's MultiplyReply.
// It simply sends the reply through the channel.
func (smc *Service) processMultiplyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*MultiplyReply)

	log.Lvl1(smc.ServerIdentity(), "Received MultiplyReply:", reply.ReqID)

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.multiplyReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
