package session

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) GetRemoteCipherID(SessionID messages.SessionID, name string,
	owner *network.ServerIdentity) (messages.CipherID, bool) {
	log.Lvl1(service.ServerIdentity(), "Retrieving remote CipherID")

	// Create GetCipherIDRequest with its ID
	reqID := messages.NewGetCipherIDRequestID()
	service.getCipherIDRepLock.Lock()
	req := &messages.GetCipherIDRequest{reqID, SessionID, name}
	service.getCipherIDRepLock.Unlock()

	// Create channel before sending request to owner.
	service.getCipherIDReplies[reqID] = make(chan *messages.GetCipherIDReply)

	// Send request to owner
	log.Lvl2(service.ServerIdentity(), "Sending GetCipherIDRequest to ciphertext owner")
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error("Couldn't send GetCipherIDRequest to owner:", err)
		return messages.NilCipherID, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetCipherIDRequest to root. Waiting on channel to receive reply...")
	service.getCipherIDRepLock.RLock()
	replyChan := service.getCipherIDReplies[reqID]
	service.getCipherIDRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.getCipherIDRepLock.Lock()
	close(replyChan)
	delete(service.getCipherIDReplies, reqID)
	service.getCipherIDRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

	return reply.CipherID, reply.Valid
}

func (service *Service) processGetCipherIDRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetCipherIDRequest)

	log.Lvl1(service.ServerIdentity(), "Owner. Received GetCipherIDRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetCipherIDReply{req.ReqID, messages.NilCipherID, false}

	// Retrieve session
	s, ok := service.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Retrieve CipherID
	id, ok := s.GetLocalCipherID(req.Name)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested CipherID does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Set fields in reply
	reply.CipherID = id
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the owner's GetCipherIDReply.
// It simply sends the reply through the channel.
func (service *Service) processGetCipherIDReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetCipherIDReply)

	log.Lvl3(service.ServerIdentity(), "Received GetCipherIDReply:", reply.ReqID)

	// Simply send reply through channel
	service.getCipherIDRepLock.RLock()
	service.getCipherIDReplies[reply.ReqID] <- reply
	service.getCipherIDRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
