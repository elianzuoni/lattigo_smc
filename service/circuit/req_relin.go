package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

// Delegates the relinearisation of the ciphertext indexed by its ID to its owner.
func (service *Service) DelegateRelinCipher(sessionID messages.SessionID, cipherID messages.CipherID) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating relinearisation:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return NilCipherID
	if cipherID == messages.NilCipherID {
		err := errors.New("The input is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create RelinRequest with its ID
	reqID := messages.NewRelinRequestID()
	req := &messages.RelinRequest{reqID, sessionID, cipherID}
	var reply *messages.RelinReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.RelinReply, 1)
	service.relinRepLock.Lock()
	service.relinReplies[reqID] = replyChan
	service.relinRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending RelinRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send RelinRequest to owner: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetRelinRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.relinRepLock.Lock()
	close(replyChan)
	delete(service.relinReplies, reqID)
	service.relinRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform relinearisation")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)

		return messages.NilCipherID, err
	}

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The RelinRequest is received by the owner of the ciphertext.
func (service *Service) processRelinRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RelinRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received RelinRequest for ciphertext")

	// Start by declaring reply with minimal fields.
	reply := &messages.RelinReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Relinearise the ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to relinearise the ciphertext")
	newCipherID, err := service.relinCipher(req.ReqID.String(), req.SessionID, req.CipherID)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not relinearise the ciphertext:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully relinearised the ciphertext")
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = newCipherID

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

// Relinearises the ciphertext indexed by its ID.
// reqID is just a prefix for logs.
func (service *Service) relinCipher(reqID string, sessionID messages.SessionID,
	cipherID messages.CipherID) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Relinearise a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}
	// Retrieving evaluation key
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving evaluation key")
	evalKey, ok := s.GetEvaluationKey()
	if !ok {
		err := errors.New("Could not retrieve evaluation key")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}
	// Check that the ciphertext has the correct degree
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Checking degree of ciphertext (cannot relinearise with degree >= 3)")
	if ct.Degree() >= 3 {
		err := errors.New("Cannot relinearise ciphertext of degree >= 3")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Relinearise
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, evalKey)

	// Store locally
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Storing the result")
	relinID := s.StoreCiphertextNewID(ctRelin)

	return relinID, nil
}

// The RelinReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateRelinCipher is waiting.
func (service *Service) processRelinReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RelinReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received RelinReply")

	// Get reply channel
	service.relinRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked RelinRepLock")
	replyChan, ok := service.relinReplies[reply.ReqID]
	service.relinRepLock.RUnlock()

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
func (service *Service) HandleRelinQuery(query *messages.RelinQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Server. Received RelinQuery for ciphertext:", query.CipherID)

	relinID, err := service.relinCipher("query", query.SessionID, query.CipherID)
	return &messages.RelinResponse{relinID, err == nil}, err
}
