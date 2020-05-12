package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

// Delegates the multiplication of the ciphertexts indexed by their IDs to the owner of the second one.
func (service *Service) DelegateMultiplyCiphers(sessionID messages.SessionID, cipherID1 messages.CipherID,
	cipherID2 messages.CipherID, withRelin bool) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating multiplication:", cipherID1, "*", cipherID2)

	// Check that none of the inputs is NilCipherID: otherwise, return NilCipherID
	if cipherID1 == messages.NilCipherID || cipherID2 == messages.NilCipherID {
		err := errors.New("One of the inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create MultiplyRequest with its ID
	reqID := messages.NewMultiplyRequestID()
	req := &messages.MultiplyRequest{reqID, sessionID, cipherID1, cipherID2,
		withRelin}

	// Create channel before sending request to root.
	service.multiplyRepLock.Lock()
	service.multiplyReplies[reqID] = make(chan *messages.MultiplyReply)
	service.multiplyRepLock.Unlock()

	// Send request to owner of second ciphertext (because why not)
	log.Lvl2(service.ServerIdentity(), "Sending MultiplyRequest to owner of second ciphertext:", reqID)
	err := service.SendRaw(cipherID2.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send MultiplyRequest to owner: " + err.Error())
		log.Error(err)
		return messages.NilCipherID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply:", reqID)
	service.multiplyRepLock.RLock()
	replyChan := service.multiplyReplies[reqID]
	service.multiplyRepLock.RUnlock()
	// Timeout
	var reply *messages.MultiplyReply
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "Got reply:", reqID)
	case <-time.After(10 * time.Second):
		log.Fatal(service.ServerIdentity(), "Did not receive reply:", reqID)
		return messages.NilCipherID, nil // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it:", reqID)
	service.multiplyRepLock.Lock()
	close(replyChan)
	delete(service.multiplyReplies, reqID)
	service.multiplyRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform multiplication")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl3(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The MultiplyRequest is received by the owner of the second ciphertext.
func (service *Service) processMultiplyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.MultiplyRequest)

	log.Lvl1(service.ServerIdentity(), "Received MultiplyRequest ", req.ReqID,
		"for product:", req.CipherID1, "*", req.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &messages.MultiplyReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Multiply the ciphertexts
	log.Lvl3(service.ServerIdentity(), "Going to multiply ciphertexts:", req.ReqID)
	newCipherID, err := service.multiplyCiphers(req.ReqID, req.SessionID, req.CipherID1, req.CipherID2)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not multiply the ciphertexts:", err)
	}
	log.Lvl3(service.ServerIdentity(), "Successfully multiplied ciphertexts:", req.ReqID)

	// If withRelin is true, relinearise and use that CipherID
	if req.WithRelin {
		log.Lvl3(service.ServerIdentity(), "Going to relinearise ciphertext:", req.ReqID)
		newCipherID, err = service.relinCipher(req.SessionID, newCipherID)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not relinearise ciphertext:", err)
		} else {
			log.Lvl3(service.ServerIdentity(), "Successfully relinearised ciphertext:", req.ReqID)
		}
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
	log.Lvl3(service.ServerIdentity(), "Sent positive reply to server:", req.ReqID)

	return
}

// Multiplies the ciphertexts indexed by their IDs. If withRelin is true, it also relinearises.
func (service *Service) multiplyCiphers(reqID messages.MultiplyRequestID, sessionID messages.SessionID,
	cipherID1 messages.CipherID, cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "Multiplying two ciphertexts:")

	// Extract Session, if existent
	log.Lvl3(service.ServerIdentity(), "Going to retrieve session:", reqID)
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Extract ciphertexts and check feasibility
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext 1:", reqID)
	ct1, ok := s.GetCiphertext(cipherID1)
	if !ok {
		err := errors.New("First ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext 2:", reqID)
	ct2, ok := s.GetCiphertext(cipherID2)
	if !ok {
		err := errors.New("Second ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Evaluate the product
	log.Lvl3(service.ServerIdentity(), "Evaluating the product of the ciphertexts:", reqID)
	eval := bfv.NewEvaluator(s.Params)
	ctMul := eval.MulNew(ct1, ct2)

	// Store locally
	mulID := s.StoreCiphertextNewID(ctMul)

	return mulID, nil
}

// The MultiplyReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateMultiplyCiphers is waiting.
func (service *Service) processMultiplyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.MultiplyReply)

	log.Lvl1(service.ServerIdentity(), "Received MultiplyReply:", reply.ReqID)

	// Simply send reply through channel
	service.multiplyRepLock.RLock()
	replyChan, ok := service.multiplyReplies[reply.ReqID]
	service.multiplyRepLock.RUnlock()

	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	replyChan <- reply

	log.Lvl3(service.ServerIdentity(), "Sent reply through channel:", reply.ReqID)

	return
}

// Legacy query
func (service *Service) HandleMultiplyQuery(query *messages.MultiplyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received MultiplyQuery:", query.CipherID1, "*", query.CipherID2)

	mulID, err := service.multiplyCiphers(messages.NewMultiplyRequestID(), query.SessionID, query.CipherID1, query.CipherID2)
	return &messages.MultiplyResponse{mulID, err == nil}, err
}
