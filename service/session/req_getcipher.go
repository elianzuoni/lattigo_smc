package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

func (service *Service) GetRemoteCiphertext(SessionID messages.SessionID,
	CipherID messages.CipherID) (*bfv.Ciphertext, bool) {
	log.Lvl1(service.ServerIdentity(), "Retrieving remote ciphertext")

	// Create GetCipherRequest with its ID
	reqID := messages.NewGetCipherRequestID()
	req := &messages.GetCipherRequest{reqID, SessionID, CipherID}

	// Create channel before sending request to owner.
	service.getCipherRepLock.Lock()
	service.getCipherReplies[reqID] = make(chan *messages.GetCipherReply)
	service.getCipherRepLock.Unlock()

	// Send request to owner
	log.Lvl2(service.ServerIdentity(), "Sending GetCipherRequest to ciphertext owner:", reqID)
	err := service.SendRaw(CipherID.GetServerIdentityOwner(), req)
	if err != nil {
		log.Error("Couldn't send GetCipherRequest to owner:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetCipherRequest to root. Waiting on channel to receive reply:", reqID)
	service.getCipherRepLock.RLock()
	//log.Lvl3(service.ServerIdentity(), "Locked getCipherRepLock:", reqID)
	replyChan := service.getCipherReplies[reqID]
	service.getCipherRepLock.RUnlock()
	// Timeout
	var reply *messages.GetCipherReply
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "Got reply:", reqID)
	case <-time.After(2 * time.Second):
		log.Fatal(service.ServerIdentity(), "Did not receive reply:", reqID)
		return nil, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it:", reqID)
	service.getCipherRepLock.Lock()
	close(replyChan)
	delete(service.getCipherReplies, reqID)
	service.getCipherRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "Closed channel, returning")

	return reply.Ciphertext, reply.Valid
}

func (service *Service) processGetCipherRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetCipherRequest)

	log.Lvl1(service.ServerIdentity(), "Owner. Received GetCipherRequest:", req.ReqID)

	// Start by declaring reply with minimal fields.
	reply := &messages.GetCipherReply{req.ReqID, nil, false}

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

	// Retrieve ciphertext
	ct, ok := s.GetCiphertext(req.CipherID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested ciphertext does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Set fields in reply
	reply.Ciphertext = ct
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server:", req.ReqID)
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
	}
	log.Lvl3(service.ServerIdentity(), "Sent positive reply to server:", req.ReqID)

	return
}

// This method is executed at the server when receiving the owner's GetCipherReply.
// It simply sends the reply through the channel.
func (service *Service) processGetCipherReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetCipherReply)

	log.Lvl2(service.ServerIdentity(), "Received GetCipherReply:", reply.ReqID)

	// Simply send reply through channel
	service.getCipherRepLock.RLock()
	//log.Lvl3(service.ServerIdentity(), "Locked getCipherRepLock:", reply.ReqID)
	replyChan, ok := service.getCipherReplies[reply.ReqID]
	service.getCipherRepLock.RUnlock()

	if !ok {
		log.Fatal(service.ServerIdentity(), "Reply channel not existent:", reply.ReqID)
	}
	replyChan <- reply

	log.Lvl3(service.ServerIdentity(), "Sent reply through channel:", reply.ReqID)

	return
}
