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
	var reply *messages.GetEvalKeyReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.GetEvalKeyReply, 1)
	service.getEvalKeyRepLock.Lock()
	service.getEvalKeyReplies[reqID] = replyChan
	service.getEvalKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GetEvalKeyRequest to owner:", reqID)
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Couldn't send GetEvalKeyRequest to root:", err)
		return nil, false
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetEvalKeyRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Did not receive reply from channel")
		return nil, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.getEvalKeyRepLock.Lock()
	close(replyChan)
	delete(service.getEvalKeyReplies, reqID)
	service.getEvalKeyRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel, returning")

	return reply.EvaluationKey, reply.Valid
}

func (service *Service) processGetEvalKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetEvalKeyRequest)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received GetEvalKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetEvalKeyReply{req.ReqID, nil, false}

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

	// Get Evaluation Key
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieving local EvaluationKey")
	s.evalKeyLock.RLock()
	evk := s.evalKey
	s.evalKeyLock.RUnlock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieved local EvaluationKey")

	// Check existence
	if evk == nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Evaluation key not generated")
		reply.EvaluationKey = nil
		reply.Valid = false
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "EvaluationKey exists")
		reply.EvaluationKey = evk
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

// This method is executed at the server when receiving the root's GetEvalKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetEvalKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetEvalKeyReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received GetEvalKeyReply")

	// Get reply channel
	service.getEvalKeyRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked getEvalKeyRepLock")
	replyChan, ok := service.getEvalKeyReplies[reply.ReqID]
	service.getEvalKeyRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}
