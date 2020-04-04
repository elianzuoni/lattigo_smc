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
	req := RelinRequest{query.SessionID, reqID, query}

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending RelinRequest to root.")
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Couldn't send RelinRequest to root: ", err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Sent RelinRequest to root. Waiting on channel to receive new CipherID...")
	reply := <-s.relinReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform sum")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	}
	// TODO: close channel?

	return &RelinResponse{reply.Valid}, nil

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
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Check feasibility
	log.Lvl3(smc.ServerIdentity(), "Checking existence of ciphertext and evaluation key")
	ct, ok := s.database[req.Query.CipherID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested ciphertext does not exist:", req.Query.CipherID)
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	if s.evalKey == nil {
		log.Error(smc.ServerIdentity(), "Evaluation key not generated")
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Relinearise
	log.Lvl3(smc.ServerIdentity(), "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, s.evalKey)

	// Register (overwrite) in local database
	s.database[req.Query.CipherID] = ctRelin

	// Send reply to server
	reply.Valid = true
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
	s.relinReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
