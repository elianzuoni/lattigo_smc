// The goal of the Key Query is to have the server retrieve the specified keys.

package session

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// HandleKeyQuery is the handler registered for message type KeyQuery: a client asks this server to retrieve keys
// from the root.
// The request is forwarded to the root, and the method returns a response based on the reply sent by the server,
// indicating which keys were retrieved.
func (service *Service) HandleKeyQuery(query *messages.KeyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received KeyQuery query. ReqRotKey:", query.RotationKey,
		"; ReqEvalKey:", query.EvaluationKey)

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create KeyRequest with its ID
	reqID := messages.NewKeyRequestID()
	req := &messages.KeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	service.keyRepLock.Lock()
	service.keyReplies[reqID] = make(chan *messages.KeyReply)
	service.keyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending KeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := service.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Could not forward query to the root: " + err.Error())
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	log.Lvl2(service.ServerIdentity(), "Forwarded request to the root")

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	service.keyRepLock.RLock()
	replyChan := service.keyReplies[reqID]
	service.keyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.keyRepLock.Lock()
	close(replyChan)
	delete(service.keyReplies, reqID)
	service.keyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	// Save (in the Service struct) the received keys.
	if reply.EvalKey != nil {
		// We don't need to hold the lock
		s.EvalKeyLock.Lock()
		s.EvalKey = reply.EvalKey
		s.EvalKeyLock.Unlock()
	}
	if reply.RotKeys != nil {
		// We don't need to hold the lock
		s.RotKeyLock.Lock()
		s.RotationKey = reply.RotKeys // TODO: overwrite no matter what?
		s.RotKeyLock.Unlock()
	}

	return &messages.KeyResponse{reply.EvalKey != nil, reply.RotKeys != nil, reply.Valid}, nil
}

// KeyQuery is received at root from server.
// It comprises two flags, signalling which keys the server is asking for.
func (service *Service) processKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.KeyRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received KeyQuery. ReqRotKey:", req.Query.RotationKey,
		"; ReqEvalKey:", req.Query.EvaluationKey)

	// Start by declaring reply with minimal fields.
	reply := &messages.KeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := service.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	if req.Query.EvaluationKey {
		// We don't need to hold the lock
		s.EvalKeyLock.RLock()
		reply.EvalKey = s.EvalKey
		s.EvalKeyLock.RUnlock()
	}
	if req.Query.RotationKey {
		// We don't need to hold the lock
		s.RotKeyLock.RLock()
		reply.RotKeys = s.RotationKey
		s.RotKeyLock.RUnlock()
	}
	reply.Valid = true

	// Send the result.
	log.Lvl2(service.ServerIdentity(), "Sending KeyReply to server", msg.ServerIdentity)
	err := service.SendRaw(msg.ServerIdentity, &reply)
	if err != nil {
		log.Error("Could not send reply : ", err)
	}
}

// This method is executed at the server when receiving the root's KeyReply.
// It just sends the reply through the channel.
func (service *Service) processKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.KeyReply)

	log.Lvl1(service.ServerIdentity(), "Server. Received KeyReply. RotKeyRcvd:", reply.RotKeys != nil,
		"EvalKeyRcvd:", reply.EvalKey != nil)

	// Simply send reply through channel
	service.keyRepLock.RLock()
	service.keyReplies[reply.ReqID] <- reply
	service.keyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")
}
