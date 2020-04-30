package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Legacy query
func (service *Service) HandleSumQuery(query *messages.SumQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SumQuery:", query.CipherID1, "+", query.CipherID2)

	/*
		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(query.SessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Create SumRequest with its ID
		reqID := messages.NewSumRequestID()
		req := &messages.SumRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.sumRepLock.Lock()
		service.sumReplies[reqID] = make(chan *messages.SumReply)
		service.sumRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending SumRequest to root:", reqID)
		tree := s.Roster.GenerateBinaryTree()
		err := service.SendRaw(tree.Root.ServerIdentity, req)
		if err != nil {
			err = errors.New("Couldn't send SumRequest to root: " + err.Error())
			log.Error(err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
		service.sumRepLock.RLock()
		replyChan := service.sumReplies[reqID]
		service.sumRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.sumRepLock.Lock()
		close(replyChan)
		delete(service.sumReplies, reqID)
		service.sumRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel")

		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't perform sum")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		} else {
			log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)
		}

		return &messages.SumResponse{reply.NewCipherID, reply.Valid}, nil

	*/

	sumID, err := service.sumCiphers(query.SessionID, query.CipherID1, query.CipherID2)
	return &messages.SumResponse{sumID, err == nil}, err
}

func (service *Service) sumCiphers(sessionID messages.SessionID, cipherID1 messages.CipherID,
	cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "Summing two ciphertexts")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Extract ciphertexts and check feasibility
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertexts")
	ct1, ok := s.GetCiphertext(cipherID1)
	if !ok {
		err := errors.New("First ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	ct2, ok := s.GetCiphertext(cipherID2)
	if !ok {
		err := errors.New("Second ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Evaluate the sum
	log.Lvl3(service.ServerIdentity(), "Evaluating the sum of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ctSum := eval.AddNew(ct1, ct2)

	// Store locally
	sumID := s.StoreCiphertextNewID(ctSum)

	return sumID, nil
}

// To be modified

// This method is executed at the root when receiving a SumRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the sum and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
func (service *Service) processSumRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SumRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received SumRequest ", req.ReqID, "for sum:",
		req.Query.CipherID1, "+", req.Query.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &messages.SumReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Check feasibility
	log.Lvl3(service.ServerIdentity(), "Checking existence of ciphertexts")
	ct1, ok := s.GetCiphertext(req.Query.CipherID1)
	if !ok {
		log.Error(service.ServerIdentity(), "Ciphertext", req.Query.CipherID1, "does not exist.")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	ct2, ok := s.GetCiphertext(req.Query.CipherID2)
	if !ok {
		log.Error(service.ServerIdentity(), "Ciphertext", req.Query.CipherID2, "does not exist.")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Evaluate the sum
	log.Lvl3(service.ServerIdentity(), "Evaluating the sum of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ct := eval.AddNew(ct1, ct2)

	// Register in local database
	newCipherID := messages.NewCipherID(service.ServerIdentity())
	s.StoreCiphertext(newCipherID, ct)

	// Set fields in reply
	reply.NewCipherID = newCipherID
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's SumReply.
// It simply sends the reply through the channel.
func (service *Service) processSumReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SumReply)

	log.Lvl1(service.ServerIdentity(), "Received SumReply:", reply.ReqID)

	// Simply send reply through channel
	service.sumRepLock.RLock()
	service.sumReplies[reply.ReqID] <- reply
	service.sumRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
