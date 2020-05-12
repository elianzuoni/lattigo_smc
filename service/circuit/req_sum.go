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

	// Create channel before sending request to root.
	service.sumRepLock.Lock()
	service.sumReplies[reqID] = make(chan *messages.SumReply)
	service.sumRepLock.Unlock()

	// Send request to owner of second ciphertext (because why not)
	log.Lvl2(service.ServerIdentity(), "Sending SumRequest to owner of second ciphertext:", reqID)
	err := service.SendRaw(cipherID2.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send SumRequest to owner: " + err.Error())
		log.Error(err)
		return messages.NilCipherID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply:", reqID)
	service.sumRepLock.RLock()
	replyChan := service.sumReplies[reqID]
	service.sumRepLock.RUnlock()
	var reply *messages.SumReply
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "Got reply:", reqID)
	case <-time.After(3 * time.Second):
		log.Fatal(service.ServerIdentity(), "Did not receive reply:", reqID)
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it:", reqID)
	service.sumRepLock.Lock()
	close(replyChan)
	delete(service.sumReplies, reqID)
	service.sumRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform sum")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The SumRequest is received by the owner of the second ciphertext.
func (service *Service) processSumRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SumRequest)

	log.Lvl1(service.ServerIdentity(), "Received SumRequest ", req.ReqID, "for sum:",
		req.CipherID1, "+", req.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &messages.SumReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Sum the ciphertexts
	newCipherID, err := service.sumCiphers(req.SessionID, req.CipherID1, req.CipherID2)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not sum the ciphertexts:", err)
	}

	// Set fields in reply
	reply.NewCipherID = newCipherID
	reply.Valid = (err == nil)

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server:", req.ReqID)
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server:", req.ReqID)

	return
}

// Sums the ciphertext indexed by their IDs.
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

// The SumReply is received by the server which sent the request. This method only sends the reply through the channel
// on which DelegateSumCiphers is waiting.
func (service *Service) processSumReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SumReply)

	log.Lvl1(service.ServerIdentity(), "Received SumReply:", reply.ReqID)

	// Simply send reply through channel
	service.sumRepLock.RLock()
	service.sumReplies[reply.ReqID] <- reply
	service.sumRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel:", reply.ReqID)

	return
}

// Legacy query
func (service *Service) HandleSumQuery(query *messages.SumQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SumQuery:", query.CipherID1, "+", query.CipherID2)

	sumID, err := service.sumCiphers(query.SessionID, query.CipherID1, query.CipherID2)
	return &messages.SumResponse{sumID, err == nil}, err
}
