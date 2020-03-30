package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's RelinQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns a valid or an invalid response, depending on what the root replied.
func (s *Service) HandleRelinearisationQuery(query *RelinQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Server. Received RelinQuery for ciphertext:", query.CipherID)

	// Create RelinRequest with its ID
	reqID := newRelinRequestID()
	req := RelinRequest{reqID, query}

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending RelinRequest to root.")
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error(s.ServerIdentity(), "Couldn't send RelinRequest to root: ", err.Error)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent RelinRequest to root. Waiting on channel to receive new CipherID...")
	reply := <-s.relinReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.valid {
		err := errors.New("Received invalid reply: root couldn't perform sum")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(s.ServerIdentity(), "Received valid reply from channel")
	}
	// TODO: close channel?

	return &RelinResponse{reply.valid}, nil

}

// This method is executed at the root when receiving a SumRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the relinearisation and stores the new ciphertext
// under the same CipherID as before and returns a valid reply.
func (s *Service) processRelinRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RelinRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received RelinRequest for ciphertext", req.CipherID)

	// Check feasibility
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertext and evaluation key")
	ct, ok := s.database[req.CipherID]
	if !ok {
		log.Error(s.ServerIdentity(), "Requested ciphertext does not exist:", req.CipherID)
		err := s.SendRaw(msg.ServerIdentity, &RelinReply{req.RelinRequestID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	if !s.evalKeyGenerated {
		log.Error(s.ServerIdentity(), "Evaluation key not generated")
		err := s.SendRaw(msg.ServerIdentity, &RelinReply{req.RelinRequestID, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Relinearise
	log.Lvl3(s.ServerIdentity(), "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, s.evalKey)

	// Register (overwrite) in local database
	s.database[req.CipherID] = ctRelin

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity, &RelinReply{req.RelinRequestID, true})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RelinReply.
// It simply sends the reply through the channel.
func (s *Service) processRelinReply(msg *network.Envelope) {
	reply := (msg.Msg).(*RelinReply)

	log.Lvl1(s.ServerIdentity(), "Received RelinReply:", reply.RelinRequestID)

	// Simply send reply through channel
	s.relinReplies[reply.RelinRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
