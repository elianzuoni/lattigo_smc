package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

func (service *Service) GetRemotePublicKey(sessionID messages.SessionID, owner *network.ServerIdentity) (*bfv.PublicKey, bool) {
	log.Lvl2(service.ServerIdentity(), "Retrieving remote public key")

	// Create GetPubKeyRequest with its ID
	reqID := messages.NewGetPubKeyRequestID()
	req := &messages.GetPubKeyRequest{reqID, sessionID}
	var reply *messages.GetPubKeyReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.GetPubKeyReply, 1)
	service.getPubKeyRepLock.Lock()
	service.getPubKeyReplies[reqID] = replyChan
	service.getPubKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GetPubKeyRequest to root")
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Couldn't send GetPubKeyRequest to root:", err)
		return nil, false
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetPubKeyRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Did not receive reply from channel")
		return nil, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.getPubKeyRepLock.Lock()
	close(replyChan)
	delete(service.getPubKeyReplies, reqID)
	service.getPubKeyRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel, returning")

	return reply.PublicKey, reply.Valid
}

func (service *Service) processGetPubKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetPubKeyRequest)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received GetPubKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetPubKeyReply{req.ReqID, nil, false}

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Requested session does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Get Public Key
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieving local Public Key")
	s.pubKeyLock.RLock()
	pk := s.publicKey
	s.pubKeyLock.RUnlock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieved local Public Key")

	// Check existence
	if pk == nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Public key not generated")
		reply.PublicKey = nil
		reply.Valid = false
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Public key exists")
		reply.PublicKey = pk
		reply.Valid = true
	}

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent reply to server:", req.ReqID)

	return
}

// This method is executed at the server when receiving the root's GetPubKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetPubKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetPubKeyReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received GetPubKeyReply")

	// Get reply channel
	service.getPubKeyRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked getPubKeyRepLock")
	replyChan, ok := service.getPubKeyReplies[reply.ReqID]
	service.getPubKeyRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}
