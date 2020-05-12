package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

func (service *Service) GetRemoteRotationKey(sessionID messages.SessionID, rotIdx int, k uint64,
	owner *network.ServerIdentity) (*bfv.RotationKeys, bool) {
	log.Lvl2(service.ServerIdentity(), "(rotIdx =", rotIdx, ", k =", k, ")\n", "Retrieving remote rotation key")

	// Create GetRotKeyRequest with its ID
	reqID := messages.NewGetRotKeyRequestID()
	req := &messages.GetRotKeyRequest{reqID, sessionID, rotIdx, k}
	var reply *messages.GetRotKeyReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.GetRotKeyReply, 1)
	service.getRotKeyRepLock.Lock()
	service.getRotKeyReplies[reqID] = replyChan
	service.getRotKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "(rotIdx =", rotIdx, ", k =", k, ")\n", "Sending GetRotKeyRequest to root:", reqID)
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Couldn't send GetRotKeyRequest to root:", err)
		return nil, false
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetRotKeyRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Did not receive reply from channel")
		return nil, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.getRotKeyRepLock.Lock()
	close(replyChan)
	delete(service.getRotKeyReplies, reqID)
	service.getRotKeyRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel, returning")

	return reply.RotationKey, reply.Valid
}

func (service *Service) processGetRotKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetRotKeyRequest)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received GetRotKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetRotKeyReply{req.ReqID, nil, false}

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

	// Reduce K modulo n/2 (each row is long n/2)
	req.K &= (1 << (s.Params.LogN - 1)) - 1

	// Only left-rotation is available. If right-rotation is requested, transform it into a left-rotation.
	if req.RotIdx == bfv.RotationRight {
		req.RotIdx = bfv.RotationLeft
		req.K = (1 << (s.Params.LogN - 1)) - req.K
	}

	// Get Rotation Key
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieving local Rotation Key")
	s.rotKeyLock.RLock()
	rotk := s.rotationKey
	s.rotKeyLock.RUnlock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieved local Rotation Key")

	// Check existence, and set fields in the reply
	if rotk == nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Rotation key not generated")
		reply.RotationKey = nil
		reply.Valid = false
	} else if req.RotIdx == bfv.RotationRow && !rotk.CanRotateRows() {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Rotation key unusable: cannot rotate rows")
		reply.RotationKey = nil
		reply.Valid = false
	} else if req.RotIdx == bfv.RotationLeft && !rotk.CanRotateLeft(req.K, uint64(1<<s.Params.LogN)) {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Rotation key unusable: cannot rotate columns of specified amount")
		reply.RotationKey = nil
		reply.Valid = false
	} else {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Rotation key exists and is usable")
		reply.RotationKey = rotk
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

// This method is executed at the server when receiving the root's GetRotKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetRotKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetRotKeyReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received GetRotKeyReply")

	// Get reply channel
	service.getRotKeyRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked getRotKeyRepLock")
	replyChan, ok := service.getRotKeyReplies[reply.ReqID]
	service.getRotKeyRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}
