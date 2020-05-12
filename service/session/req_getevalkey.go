package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

func (service *Service) GetRemoteEvalKey(sessionID messages.SessionID, owner *network.ServerIdentity) (*bfv.EvaluationKey, bool) {
	log.Lvl2(service.ServerIdentity(), "Retrieving remote evaluation key")

	// Create GetEvalKeyRequest with its ID
	reqID := messages.NewGetEvalKeyRequestID()
	req := &messages.GetEvalKeyRequest{reqID, sessionID}

	// Create channel before sending request to root.
	service.getEvalKeyRepLock.Lock()
	service.getEvalKeyReplies[reqID] = make(chan *messages.GetEvalKeyReply)
	service.getEvalKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GetEvalKeyRequest to owner:", reqID)
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "Couldn't send GetEvalKeyRequest to root:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetEvalKeyRequest to root. Waiting on channel to receive reply:", reqID)
	service.getEvalKeyRepLock.RLock()
	replyChan := service.getEvalKeyReplies[reqID]
	service.getEvalKeyRepLock.RUnlock()
	// Timeout
	var reply *messages.GetEvalKeyReply
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "Got reply:", reqID)
	case <-time.After(3 * time.Second):
		log.Fatal(service.ServerIdentity(), "Did not receive reply:", reqID)
		return nil, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it:", reqID)
	service.getEvalKeyRepLock.Lock()
	close(replyChan)
	delete(service.getEvalKeyReplies, reqID)
	service.getEvalKeyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

	return reply.EvaluationKey, reply.Valid
}

func (service *Service) processGetEvalKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetEvalKeyRequest)

	log.Lvl2(service.ServerIdentity(), "Root. Received GetEvalKeyRequest:", req.ReqID)

	// Start by declaring reply with minimal fields.
	reply := &messages.GetEvalKeyReply{req.ReqID, nil, false}

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Get Evaluation Key
	s.evalKeyLock.RLock()
	evk := s.evalKey
	s.evalKeyLock.RUnlock()

	// Check existence
	if evk == nil {
		log.Error(service.ServerIdentity(), "Evaluation key not generated")
		reply.EvaluationKey = nil
		reply.Valid = false
	} else {
		reply.EvaluationKey = evk
		reply.Valid = true
	}

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending reply to server:", req.ReqID)
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
		return
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server:", req.ReqID)

	return
}

// This method is executed at the server when receiving the root's GetEvalKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetEvalKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetEvalKeyReply)

	log.Lvl2(service.ServerIdentity(), "Received GetEvalKeyReply:", reply.ReqID)

	// Simply send reply through channel
	service.getEvalKeyRepLock.RLock()
	service.getEvalKeyReplies[reply.ReqID] <- reply
	service.getEvalKeyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel:", reply.ReqID)

	return
}
