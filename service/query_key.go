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
		PubKeyObtained:  reply.pk != nil,
		EvalKeyObtained: reply.evk != nil,
		RotKeyObtained:  reply.rtk != nil,
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
		reply.pk = s.MasterPublicKey
	}
	if query.EvaluationKey && s.evalKeyGenerated {
		reply.evk = s.evalKey
	}
	if query.RotationKey && s.rotKeyGenerated {
		reply.rtk = s.rotationKey
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
	log.Lvl1(s.ServerIdentity(), "Server. Received KeyReply. PubKeyRcvd:", reply.pk != nil,
		"; RotKeyRcvd:", reply.rtk != nil, "EvalKeyRcvd:", reply.evk != nil)

	// Save (in the Service struct) the received keys.
	if reply.pk != nil {
		s.MasterPublicKey = reply.pk
	}
	if reply.evk != nil {
		s.evalKey = reply.evk
	}
	if reply.rtk != nil {
		s.rotationKey = reply.rtk
	}

	// Send reply through channel
	s.keyReplies[reply.KeyRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")
}
