package session

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

func (service *Service) GetRemoteCipherID(SessionID messages.SessionID, name string,
	owner *network.ServerIdentity) (messages.CipherID, bool) {
	log.Lvl1(service.ServerIdentity(), "(name =", name, ")\n", "Retrieving remote CipherID")

	// Create GetCipherIDRequest with its ID
	reqID := messages.NewGetCipherIDRequestID()
	req := &messages.GetCipherIDRequest{reqID, SessionID, name}
	var reply *messages.GetCipherIDReply

	// Create channel before sending request to owner.
	replyChan := make(chan *messages.GetCipherIDReply, 1)
	service.getCipherIDRepLock.Lock()
	service.getCipherIDReplies[reqID] = replyChan
	service.getCipherIDRepLock.Unlock()

	// Send request to owner
	log.Lvl2(service.ServerIdentity(), "(name =", name, ")\n", "Sending GetCipherIDRequest to ciphertext owner:", reqID)
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Couldn't send GetCipherIDRequest to owner:", err)
		return messages.NilCipherID, false
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(name =", name, ", ReqID =", reqID, ")\n", "Sent GetCipherIDRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(name =", name, ", ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		log.Fatal(service.ServerIdentity(), "(name =", name, ", ReqID =", reqID, ")\n", "Did not receive reply from channel")
		return messages.NilCipherID, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(name =", name, ", ReqID =", reqID, ")\n", "Received reply from channel. Closing it")
	service.getCipherIDRepLock.Lock()
	close(replyChan)
	delete(service.getCipherIDReplies, reqID)
	service.getCipherIDRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "Closed channel, returning")

	return reply.CipherID, reply.Valid
}

func (service *Service) processGetCipherIDRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetCipherIDRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Owner. Received GetCipherIDRequest")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetCipherIDReply{req.ReqID, messages.NilCipherID, false}

	// Retrieve session
	s, ok := service.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Requested session does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Retrieve CipherID
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieving local CipherID")
	id, ok := s.GetLocalCipherID(req.Name)
	if !ok {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Requested CipherID does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply (negatively) to server:", err)
		}

		return
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieved local CipherID")

	// Set fields in reply
	reply.CipherID = id
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server:")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the owner's GetCipherIDReply.
// It simply sends the reply through the channel.
func (service *Service) processGetCipherIDReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetCipherIDReply)

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received GetCipherIDReply")

	// Get reply channel
	service.getCipherIDRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked getCipherIDRepLock")
	replyChan, ok := service.getCipherIDReplies[reply.ReqID]
	service.getCipherIDRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}
