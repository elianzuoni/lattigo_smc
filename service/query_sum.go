package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's SumQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (s *Service) HandleSumQuery(query *SumQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received SumQuery:", query.CipherID1, "+", query.CipherID2)

	// Create SumRequest with its ID
	reqID := newSumRequestID()
	req := SumRequest{reqID, query}

	// Create channel before sending request to root.
	s.sumReplies[reqID] = make(chan *SumReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending SumRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send SumRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent SumRequest to root. Waiting on channel to receive reply...")
	reply := <-s.sumReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.valid {
		err := errors.New("Received invalid reply: root couldn't perform sum")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(s.ServerIdentity(), "Received valid reply from channel:", reply.newCipherID)
	}
	// TODO: close channel?

	return &SumResponse{reply.newCipherID, reply.valid}, nil
}

// This method is executed at the root when receiving a SumRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the sum and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
func (s *Service) processSumRequest(msg *network.Envelope) {
	req := (msg.Msg).(*SumRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received SumRequest ", req.SumRequestID, "for sum:",
		req.CipherID1, "+", req.CipherID2)

	// Check feasibility
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertexts")
	ct1, ok := s.database[req.CipherID1]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.CipherID1, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, &SumReply{req.SumRequestID, NilCipherID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	ct2, ok := s.database[req.CipherID2]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.CipherID2, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, &SumReply{req.SumRequestID, NilCipherID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Evaluate the sum
	log.Lvl3(s.ServerIdentity(), "Evaluating the sum of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ct := eval.AddNew(ct1, ct2)

	// Register in local database
	newCipherID := newCipherID()
	s.database[newCipherID] = ct

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity, &SumReply{req.SumRequestID, newCipherID, true})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's SumReply.
// It simply sends the reply through the channel.
func (s *Service) processSumReply(msg *network.Envelope) {
	reply := (msg.Msg).(*SumReply)

	log.Lvl1(s.ServerIdentity(), "Received SumReply:", reply.SumRequestID)

	// Simply send reply through channel
	s.sumReplies[reply.SumRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
