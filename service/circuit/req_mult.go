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
	var reply *messages.MultiplyReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.MultiplyReply, 1)
	service.multiplyRepLock.Lock()
	service.multiplyReplies[reqID] = replyChan
	service.multiplyRepLock.Unlock()

	// Send request to owner of second ciphertext (because why not)
	log.Lvl2(service.ServerIdentity(), "Sending MultiplyRequest to owner of second ciphertext:", reqID)
	err := service.SendRaw(cipherID2.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send MultiplyRequest to owner: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetMultiplyRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it")
	service.multiplyRepLock.Lock()
	close(replyChan)
	delete(service.multiplyReplies, reqID)
	service.multiplyRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform multiplication")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)

		return messages.NilCipherID, err
	}

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The MultiplyRequest is received by the owner of the second ciphertext.
func (service *Service) processMultiplyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.MultiplyRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received MultiplyRequest",
		"for product:", req.CipherID1, "*", req.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &messages.MultiplyReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Multiply the ciphertexts
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to multiply ciphertexts")
	newCipherID, err := service.multiplyCiphers(req.ReqID.String(), req.SessionID, req.CipherID1, req.CipherID2)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not multiply the ciphertexts:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully multiplied ciphertexts")
	}

	// If withRelin is true, relinearise and use that CipherID
	if err == nil && req.WithRelin {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Also going to relinearise ciphertext")
		newCipherID, err = service.relinCipher(req.ReqID.String(), req.SessionID, newCipherID)
		if err != nil {
			log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not relinearise ciphertext:", err)
		} else {
			log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully relinearised ciphertext")
		}
	}

	// Set fields in reply
	reply.NewCipherID = newCipherID
	reply.Valid = (err == nil)

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server:")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent reply to server")

	return
}

// Multiplies the ciphertexts indexed by their IDs.
// reqID is just a prefix for logs.
func (service *Service) multiplyCiphers(reqID string, sessionID messages.SessionID,
	cipherID1 messages.CipherID, cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Multiplying two ciphertexts:")

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

	// Evaluate the product
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Evaluating the product of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ctMul := eval.MulNew(ct1, ct2)

	// Store locally
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Storing the result")
	mulID := s.StoreCiphertextNewID(ctMul)

	return mulID, nil
}

// The MultiplyReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateMultiplyCiphers is waiting.
func (service *Service) processMultiplyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.MultiplyReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received MultiplyReply")

	// Get reply channel
	service.multiplyRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked MultiplyRepLock")
	replyChan, ok := service.multiplyReplies[reply.ReqID]
	service.multiplyRepLock.RUnlock()

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
func (service *Service) HandleMultiplyQuery(query *messages.MultiplyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received MultiplyQuery:", query.CipherID1, "*", query.CipherID2)

	mulID, err := service.multiplyCiphers("query", query.SessionID, query.CipherID1, query.CipherID2)
	return &messages.MultiplyResponse{mulID, err == nil}, err
}
