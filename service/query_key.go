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
func (s *Service) HandleKeyQuery(query *KeyQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received KeyQuery query. ReqPubKey:", query.PublicKey, "; ReqRotKey:", query.RotationKey,
		"; ReqEvalKey:", query.EvaluationKey)

	// Create KeyRequest with its ID
	reqID := newKeyRequestID()
	req := KeyRequest{reqID, query}

	// Create channel before sending request to root.
	s.keyReplies[reqID] = make(chan *KeyReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending KeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Could not forward query to the root: " + err.Error())
		log.Error(s.ServerIdentity(), err)
		return nil, err
	}

	log.Lvl2(s.ServerIdentity(), "Forwarded request to the root")

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent KeyRequest to root. Waiting on channel to receive reply...")
	reply := <-s.keyReplies[reqID] // TODO: timeout if root cannot send reply

	log.Lvl4(s.ServerIdentity(), "Received reply from channel")
	// TODO: close channel?

	return &KeyResponse{
		PubKeyObtained:  reply.PublicKey != nil,
		EvalKeyObtained: reply.EvalKey != nil,
		RotKeyObtained:  reply.RotKeys != nil,
	}, nil
}

// KeyQuery is received at root from server.
// It comprises three flags, signalling which keys the server is asking for.
func (s *Service) processKeyRequest(msg *network.Envelope) {
	query := (msg.Msg).(*KeyQuery)

	log.Lvl1(s.ServerIdentity(), "Root. Received KeyQuery. ReqPubKey:", query.PublicKey, "; ReqRotKey:",
		query.RotationKey, "; ReqEvalKey:", query.EvaluationKey)

	// Build reply as desired by server.
	reply := KeyReply{}
	if query.PublicKey && s.pubKeyGenerated {
		reply.PublicKey = s.MasterPublicKey
	}
	if query.EvaluationKey && s.evalKeyGenerated {
		reply.EvalKey = s.evalKey
	}
	if query.RotationKey && s.rotKeyGenerated {
		reply.RotKeys = s.rotationKey
	}
	// TODO what about rotationIdx?

	// Send the result.
	log.Lvl2(s.ServerIdentity(), "Sending KeyReply to server", msg.ServerIdentity)
	err := s.SendRaw(msg.ServerIdentity, &reply)
	if err != nil {
		log.Error("Could not send reply : ", err)
	}
}

// This method is executed at the server when receiving the root's KeyReply.
// It stores the received keys, then it sends the reply through the channel.
func (s *Service) processKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*KeyReply)
	log.Lvl1(s.ServerIdentity(), "Server. Received KeyReply. PubKeyRcvd:", reply.PublicKey != nil,
		"; RotKeyRcvd:", reply.RotKeys != nil, "EvalKeyRcvd:", reply.EvalKey != nil)

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
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")
}
