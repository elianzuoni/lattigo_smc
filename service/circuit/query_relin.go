package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Handles the client's RelinQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns a valid or an invalid response, depending on what the root replied.
func (service *Service) HandleRelinearisationQuery(query *messages.RelinQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Server. Received RelinQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create RelinRequest with its ID
	reqID := messages.NewRelinRequestID()
	req := &messages.RelinRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	service.relinRepLock.Lock()
	service.relinReplies[reqID] = make(chan *messages.RelinReply)
	service.relinRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending RelinRequest to root.")
	tree := s.Roster.GenerateBinaryTree()
	err := service.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "Couldn't send RelinRequest to root: ", err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
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
		err := errors.New("Received invalid reply: root couldn't perform relinearisation")
		log.Error(service.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")
	}

	return &messages.RelinResponse{reply.NewCipherID, reply.Valid}, nil

}

// This method is executed at the root when receiving a SumRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the relinearisation and stores the new ciphertext
// under the same CipherID as before and returns a valid reply.
func (service *Service) processRelinRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RelinRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received RelinRequest for ciphertext", req.Query.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.RelinReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

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

	// Check existence of ciphertext
	log.Lvl3(service.ServerIdentity(), "Checking existence of ciphertext")
	ct, ok := s.GetCiphertext(req.Query.CipherID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested ciphertext does not exist:", req.Query.CipherID)
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// Check existence of evaluation key
	log.Lvl3(service.ServerIdentity(), "Checking existence of evaluation key")
	evalKey, ok := s.GetEvaluationKey()
	if !ok {
		log.Error(service.ServerIdentity(), "Evaluation key not generated")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// Check that the ciphertext has the correct degree
	log.Lvl3(service.ServerIdentity(), "Checking degree of ciphertext (cannot relinearise with degree >= 3)")
	if ct.Degree() >= 3 {
		log.Error(service.ServerIdentity(), "Cannot relinearise ciphertext of degree >= 3")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Relinearise
	log.Lvl3(service.ServerIdentity(), "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, evalKey)

	// Register in local database
	newCipherID := messages.NewCipherID(service.ServerIdentity())
	s.StoreCiphertext(newCipherID, ctRelin)

	// Set fields in reply
	reply.Valid = true
	reply.NewCipherID = newCipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RelinReply.
// It simply sends the reply through the channel.
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
