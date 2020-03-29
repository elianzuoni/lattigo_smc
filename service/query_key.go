package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// HandleKeyQuery is the handler registered for message type KeyQuery: a client asks this server to retrieve keys
// from the root.
// The request is forwarded to the root as-is, and the method returns a positive response without waiting for
// the response.
// The root, however, does send a response, handled in the processKeyReply method.
func (s *Service) HandleKeyQuery(query *KeyQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received KeyQuery query. ReqPubKey:", query.PublicKey, "; ReqRotKey:", query.RotationKey,
		"; ReqEvalKey:", query.EvaluationKey)

	// Forward query to the root as-is.
	log.Lvl2(s.ServerIdentity(), "Forwarding request to the root")
	tree := s.Roster.GenerateBinaryTree()
	req := (*KeyRequest)(query)
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Could not forward query to the root: " + err.Error())
		log.Error(s.ServerIdentity(), err)
		return nil, err
	}

	log.Lvl2(s.ServerIdentity(), "Forwarded request to the root")

	return nil, nil // TODO: fix
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
		reply.EvaluationKey = s.EvaluationKey
	}
	if query.RotationKey && s.rotKeyGenerated {
		reply.RotationKeys = s.rotationKey
	}
	// TODO what about rotationIdx?

	// Send the result.
	log.Lvl2(s.ServerIdentity(), "Sending KeyReply to server", msg.ServerIdentity)
	err := s.SendRaw(msg.ServerIdentity, &reply)
	if err != nil {
		log.Error("Could not send reply : ", err)
	}
}

// KeyReply is received at server from root.
// This method only parses the received KeyReply: there is no waiting goroutine to wake up.
func (s *Service) processKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*KeyReply)
	log.Lvl1(s.ServerIdentity(), "Server. Received KeyReply. PubKeyRcvd:", reply.PublicKey != nil,
		"; RotKeyRcvd:", reply.RotationKeys != nil, "EvalKeyRcvd:", reply.EvaluationKey != nil)

	// Save (in the Service struct) the received keys.
	if reply.PublicKey != nil {
		s.MasterPublicKey = reply.PublicKey
	}
	if reply.EvaluationKey != nil {
		s.EvaluationKey = reply.EvaluationKey
	}
	if reply.RotationKeys != nil {
		s.rotationKey = reply.RotationKeys
	}
}
