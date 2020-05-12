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
	log.Lvl1(service.ServerIdentity(), "(CipherID =", CipherID, ")\n", "Retrieving remote ciphertext")

	// Create GetCipherRequest with its ID
	reqID := messages.NewGetCipherRequestID()
	req := &messages.GetCipherRequest{reqID, SessionID, CipherID}
	var reply *messages.GetCipherReply

	// Create channel before sending request to owner.
	replyChan := make(chan *messages.GetCipherReply, 1)
	service.getCipherRepLock.Lock()
	service.getCipherReplies[reqID] = replyChan
	service.getCipherRepLock.Unlock()

	// Send request to owner
	log.Lvl2(service.ServerIdentity(), "(CipherID =", CipherID, ")\n", "Sending GetCipherRequest to ciphertext owner:", reqID)
	err := service.SendRaw(CipherID.GetServerIdentityOwner(), req)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Couldn't send GetCipherRequest to owner:", err)
		return nil, false
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(CipherID =", CipherID, ", ReqID =", reqID, ")\n", "Sent GetCipherRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(CipherID =", CipherID, ", ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		log.Fatal(service.ServerIdentity(), "(CipherID =", CipherID, ", ReqID =", reqID, ")\n", "Did not receive reply from channel")
		return nil, false // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(CipherID =", CipherID, ", ReqID =", reqID, ")\n", "Received reply from channel. Closing it:", reqID)
	service.getCipherRepLock.Lock()
	close(replyChan)
	delete(service.getCipherReplies, reqID)
	service.getCipherRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(CipherID =", CipherID, ", ReqID =", reqID, ")\n", "Closed channel, returning")

	return reply.Ciphertext, reply.Valid
}

func (service *Service) processGetCipherRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetCipherRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Owner. Received GetCipherRequest")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetCipherReply{req.ReqID, nil, false}

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

	// Retrieve ciphertext
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieving ciphertext.")
	ct, ok := s.GetCiphertext(req.CipherID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested ciphertext does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Retrieved ciphertext.")

	// Set fields in reply
	reply.Ciphertext = ct
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending positive reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the owner's GetCipherReply.
// It simply sends the reply through the channel.
func (service *Service) processGetCipherReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetCipherReply)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received GetCipherReply")

	// Get reply channel
	service.getCipherRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked getCipherRepLock")
	replyChan, ok := service.getCipherReplies[reply.ReqID]
	service.getCipherRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Reply channel not existent")
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}
