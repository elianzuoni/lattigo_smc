package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Handles the client's MultiplyQuery. Forwards the query to root, and waits for reply on a channel.
// Either returns the new CipherID or an invalid response, depending on what the root replied.
func (service *Service) HandleMultiplyQuery(query *messages.MultiplyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received MultiplyQuery:", query.CipherID1, "*", query.CipherID2)

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create MultiplyRequest with its ID
	reqID := messages.NewMultiplyRequestID()
	req := &messages.MultiplyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.MultiplyRepLock.Lock()
	s.MultiplyReplies[reqID] = make(chan *messages.MultiplyReply)
	s.MultiplyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending MulitplyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := service.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send MultiplyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.MultiplyRepLock.RLock()
	replyChan := s.MultiplyReplies[reqID]
	s.MultiplyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	s.MultiplyRepLock.Lock()
	close(replyChan)
	delete(s.MultiplyReplies, reqID)
	s.MultiplyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform multiplication")
		log.Error(service.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)
	}

	return &messages.MultiplyResponse{reply.NewCipherID, reply.Valid}, nil
}

// This method is executed at the root when receiving a MultiplyRequest.
// It checks for feasibility (whether or not it possesses the two requested ciphertexts) and, based
// on the result, it either returns an invalid reply, or performs the multiplication and stores the new
// ciphertext under a new CipherID which is returned in a valid reply.
func (service *Service) processMultiplyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.MultiplyRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received MultiplyRequest ", req.ReqID,
		"for product:", req.Query.CipherID1, "*", req.Query.CipherID2)

	// Start by declaring reply with minimal fields.
	reply := &messages.MultiplyReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

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

	// Check feasibilty
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

	// Evaluate multiplication
	log.Lvl3(service.ServerIdentity(), "Evaluating multiplication of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	ct := eval.MulNew(ct1, ct2)

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

// This method is executed at the server when receiving the root's MultiplyReply.
// It simply sends the reply through the channel.
func (service *Service) processMultiplyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.MultiplyReply)

	log.Lvl1(service.ServerIdentity(), "Received MultiplyReply:", reply.ReqID)

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(reply.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.MultiplyRepLock.RLock()
	s.MultiplyReplies[reply.ReqID] <- reply
	s.MultiplyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
