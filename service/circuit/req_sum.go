package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

// Delegates the sum of the ciphertexts indexed by their IDs to the owner of the second one.
func (service *Service) DelegateSumCiphers(sessionID messages.SessionID, cipherID1 messages.CipherID,
	cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating sum:", cipherID1, "+", cipherID2)

	// Check that none of the inputs is NilCipherID: otherwise, return NilCipherID
	if cipherID1 == messages.NilCipherID || cipherID2 == messages.NilCipherID {
		err := errors.New("One of the inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create SumRequest with its ID
	reqID := messages.NewSumRequestID()
	req := &messages.SumRequest{reqID, sessionID, cipherID1, cipherID2}
	var reply *messages.SumReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.SumReply, 1)
	service.sumRepLock.Lock()
	service.sumReplies[reqID] = replyChan
	service.sumRepLock.Unlock()

	// Send request to owner of second ciphertext (because why not)
	log.Lvl2(service.ServerIdentity(), "Sending SumRequest to owner of second ciphertext:", reqID)
	err := service.SendRaw(cipherID2.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send SumRequest to owner: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetSumRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it:", reqID)
	service.sumRepLock.Lock()
	close(replyChan)
	delete(service.sumReplies, reqID)
	service.sumRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform sum")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)

		return messages.NilCipherID, err
	}

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The SumRequest is received by the owner of the second ciphertext.
func (service *Service) processSumRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SumRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received SumRequest for sum:",
		req.CipherID1, "+", req.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &messages.SumReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Sum the ciphertexts
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to sum ciphertexts")
	newCipherID, err := service.sumCiphers(req.ReqID.String(), req.SessionID, req.CipherID1, req.CipherID2)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not sum the ciphertexts:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully summed ciphertexts")
	}

	// Set fields in reply
	reply.NewCipherID = newCipherID
	reply.Valid = (err == nil)

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent reply to server")

	return
}

// Sums the ciphertext indexed by their IDs.
// reqID is just a prefix for logs.
func (service *Service) sumCiphers(reqID string, sessionID messages.SessionID, cipherID1 messages.CipherID,
	cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Summing two ciphertexts")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Extract ciphertexts and check feasibility
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving first ciphertext")
	ct1, ok := s.GetCiphertext(cipherID1)
	if !ok {
		err := errors.New("First ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving second ciphertext")
	ct2, ok := s.GetCiphertext(cipherID2)
	if !ok {
		err := errors.New("Second ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Evaluate the sum
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Evaluating the sum of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ctSum := eval.AddNew(ct1, ct2)

	// Store locally
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Storing the result")
	sumID := s.StoreCiphertextNewID(ctSum)

	return sumID, nil
}

// The SumReply is received by the server which sent the request. This method only sends the reply through the channel
// on which DelegateSumCiphers is waiting.
func (service *Service) processSumReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SumReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received SumReply")

	// Get reply channel
	service.sumRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked SumRepLock")
	replyChan, ok := service.sumReplies[reply.ReqID]
	service.sumRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleSumQuery(query *messages.SumQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SumQuery:", query.CipherID1, "+", query.CipherID2)

	sumID, err := service.sumCiphers("query", query.SessionID, query.CipherID1, query.CipherID2)
	return &messages.SumResponse{sumID, err == nil}, err
}
