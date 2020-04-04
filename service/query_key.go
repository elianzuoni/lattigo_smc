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
	log.Lvl1(smc.ServerIdentity(), "Received KeyQuery query. ReqPubKey:", query.PublicKey, "; ReqRotKey:", query.RotationKey,
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
	req := KeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.keyReplies[reqID] = make(chan *KeyReply)

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
	log.Lvl3(smc.ServerIdentity(), "Sent KeyRequest to root. Waiting on channel to receive reply...")
	reply := <-s.keyReplies[reqID] // TODO: timeout if root cannot send reply

	log.Lvl4(smc.ServerIdentity(), "Received reply from channel")
	// TODO: close channel?

	return &KeyResponse{
		PubKeyObtained:  reply.PublicKey != nil,
		EvalKeyObtained: reply.EvalKey != nil,
		RotKeyObtained:  reply.RotKeys != nil,
		Valid:           reply.Valid,
	}, nil
}

// KeyQuery is received at root from server.
// It comprises three flags, signalling which keys the server is asking for.
func (smc *Service) processKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*KeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received KeyQuery. ReqPubKey:", req.Query.PublicKey, "; ReqRotKey:",
		req.Query.RotationKey, "; ReqEvalKey:", req.Query.EvaluationKey)

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

	if req.Query.PublicKey && s.MasterPublicKey != nil {
		reply.PublicKey = s.MasterPublicKey
	}
	if req.Query.EvaluationKey && s.evalKey != nil {
		reply.EvalKey = s.evalKey
	}
	if req.Query.RotationKey && s.rotationKey != nil {
		reply.RotKeys = s.rotationKey
	}
	reply.Valid = true
	// TODO what about rotationIdx?

	// Send the result.
	log.Lvl2(smc.ServerIdentity(), "Sending KeyReply to server", msg.ServerIdentity)
	err := smc.SendRaw(msg.ServerIdentity, &reply)
	if err != nil {
		log.Error("Could not send reply : ", err)
	}
}

// This method is executed at the server when receiving the root's KeyReply.
// It stores the received keys, then it sends the reply through the channel.
func (smc *Service) processKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*KeyReply)
	log.Lvl1(smc.ServerIdentity(), "Server. Received KeyReply. PubKeyRcvd:", reply.PublicKey != nil,
		"; RotKeyRcvd:", reply.RotKeys != nil, "EvalKeyRcvd:", reply.EvalKey != nil)

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Save (in the Service struct) the received keys.
	if reply.PublicKey != nil {
		s.MasterPublicKey = reply.PublicKey
	}
	if reply.EvalKey != nil {
		s.evalKey = reply.EvalKey
	}
	if reply.RotKeys != nil {
		s.rotationKey = reply.RotKeys
	}

	// Send reply through channel
	s.keyReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")
}
