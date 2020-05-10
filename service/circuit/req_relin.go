package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Delegates the relinearisation of the ciphertext indexed by its ID to its owner.
func (service *Service) DelegateRelinCipher(sessionID messages.SessionID, cipherID messages.CipherID) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating relinearisation:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return NilCipherID
	if cipherID == messages.NilCipherID {
		err := errors.New("The inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create RelinRequest with its ID
	reqID := messages.NewRelinRequestID()
	req := &messages.RelinRequest{reqID, sessionID, cipherID}

	// Create channel before sending request to root.
	service.relinRepLock.Lock()
	service.relinReplies[reqID] = make(chan *messages.RelinReply)
	service.relinRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending RelinRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send RelinRequest to owner: " + err.Error())
		log.Error(err)
		return messages.NilCipherID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply...")
	service.relinRepLock.RLock()
	replyChan := service.relinReplies[reqID]
	service.relinRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.relinRepLock.Lock()
	close(replyChan)
	delete(service.relinReplies, reqID)
	service.relinRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform relinearisation")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The RelinRequest is received by the owner of the ciphertext.
func (service *Service) processRelinRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RelinRequest)

	log.Lvl1(service.ServerIdentity(), "Received RelinRequest for ciphertext", req.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.RelinReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Relinearise the ciphertext
	newCipherID, err := service.relinCipher(req.SessionID, req.CipherID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not relinearise the ciphertext:", err)
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = newCipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// Relinearises the ciphertext indexed by its ID.
func (service *Service) relinCipher(sessionID messages.SessionID, cipherID messages.CipherID) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "Relinearising ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	// Retrieving evaluation key
	log.Lvl3(service.ServerIdentity(), "Retrieving evaluation key")
	evalKey, ok := s.GetEvaluationKey()
	if !ok {
		err := errors.New("Could not retrieve evaluation key")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	// Check that the ciphertext has the correct degree
	log.Lvl3(service.ServerIdentity(), "Checking degree of ciphertext (cannot relinearise with degree >= 3)")
	if ct.Degree() >= 3 {
		err := errors.New("Cannot relinearise ciphertext of degree >= 3")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Relinearise
	log.Lvl3(service.ServerIdentity(), "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, evalKey)

	// Store locally
	relinID := s.StoreCiphertextNewID(ctRelin)

	return relinID, nil
}

// The MultiplyReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateRelinCipher is waiting.
func (service *Service) processRelinReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RelinReply)

	log.Lvl1(service.ServerIdentity(), "Received RelinReply:", reply.ReqID)

	// Simply send reply through channel
	service.relinRepLock.RLock()
	service.relinReplies[reply.ReqID] <- reply
	service.relinRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleRelinQuery(query *messages.RelinQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Server. Received RelinQuery for ciphertext:", query.CipherID)

	relinID, err := service.relinCipher(query.SessionID, query.CipherID)
	return &messages.RelinResponse{relinID, err == nil}, err
}
