// The goal of the Key Query is to have the server retrieve the specified keys.

package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// HandleKeyQuery is the handler registered for message type KeyQuery: a client asks this server to retrieve keys
// from the root.
// The request is forwarded to the root, and the method returns a response based on the reply sent by the server,
// indicating which keys were retrieved.
func (smc *Service) HandleKeyQuery(query *KeyQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received KeyQuery query. ReqRotKey:", query.RotationKey,
		"; ReqEvalKey:", query.EvaluationKey)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create KeyRequest with its ID
	reqID := newKeyRequestID()
	req := &KeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.keyRepLock.Lock()
	s.keyReplies[reqID] = make(chan *KeyReply)
	s.keyRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending KeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Could not forward query to the root: " + err.Error())
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	log.Lvl2(smc.ServerIdentity(), "Forwarded request to the root")

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.keyRepLock.RLock()
	replyChan := s.keyReplies[reqID]
	s.keyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.keyRepLock.Lock()
	close(replyChan)
	delete(s.keyReplies, reqID)
	s.keyRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	// Save (in the Service struct) the received keys.
	if reply.EvalKey != nil {
		// We don't need to hold the lock
		s.evalKeyLock.Lock()
		s.evalKey = reply.EvalKey
		s.evalKeyLock.Unlock()
	}
	if reply.RotKeys != nil {
		// We don't need to hold the lock
		s.rotKeyLock.Lock()
		s.rotationKey = reply.RotKeys // TODO: overwrite no matter what?
		s.rotKeyLock.Unlock()
	}

	return &KeyResponse{reply.EvalKey != nil, reply.RotKeys != nil, reply.Valid}, nil
}

// KeyQuery is received at root from server.
// It comprises two flags, signalling which keys the server is asking for.
func (smc *Service) processKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*KeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received KeyQuery. ReqRotKey:", req.Query.RotationKey,
		"; ReqEvalKey:", req.Query.EvaluationKey)

	// Start by declaring reply with minimal fields.
	reply := &KeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

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

	if req.Query.EvaluationKey {
		// We don't need to hold the lock
		s.evalKeyLock.RLock()
		reply.EvalKey = s.evalKey
		s.evalKeyLock.RUnlock()
	}
	if req.Query.RotationKey {
		// We don't need to hold the lock
		s.rotKeyLock.RLock()
		reply.RotKeys = s.rotationKey
		s.rotKeyLock.RUnlock()
	}
	reply.Valid = true

	// Send the result.
	log.Lvl2(smc.ServerIdentity(), "Sending KeyReply to server", msg.ServerIdentity)
	err := smc.SendRaw(msg.ServerIdentity, &reply)
	if err != nil {
		log.Error("Could not send reply : ", err)
	}
}

// This method is executed at the server when receiving the root's KeyReply.
// It just sends the reply through the channel.
func (smc *Service) processKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*KeyReply)
	log.Lvl1(smc.ServerIdentity(), "Server. Received KeyReply. RotKeyRcvd:", reply.RotKeys != nil,
		"EvalKeyRcvd:", reply.EvalKey != nil)

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.keyRepLock.RLock()
	s.keyReplies[reply.ReqID] <- reply
	s.keyRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")
}
