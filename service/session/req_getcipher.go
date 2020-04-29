package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) GetRemoteCiphertext(SessionID messages.SessionID,
	CipherID messages.CipherID) (*bfv.Ciphertext, bool) {
	log.Lvl1(service.ServerIdentity(), "Retrieving remote ciphertext")

	// Create CloseSessionRequest with its ID
	reqID := messages.NewGetCipherRequestID()
	service.getCipherRepLock.Lock()
	req := &messages.GetCipherRequest{reqID, SessionID, CipherID}
	service.getCipherRepLock.Unlock()

	// Create channel before sending request to owner.
	service.getCipherReplies[reqID] = make(chan *messages.GetCipherReply)

	// Send request to owner
	log.Lvl2(service.ServerIdentity(), "Sending GetCipherRequest to ciphertext owner")
	err := service.SendRaw(CipherID.GetServerIdentityOwner(), req)
	if err != nil {
		log.Error("Couldn't send GetCipherRequest to owner:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetCipherRequest to root. Waiting on channel to receive reply...")
	service.getCipherRepLock.RLock()
	replyChan := service.getCipherReplies[reqID]
	service.getCipherRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.getCipherRepLock.Lock()
	close(replyChan)
	delete(service.getCipherReplies, reqID)
	service.getCipherRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

	return reply.Ciphertext, reply.Valid
}

func (service *Service) processGetCipherRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetCipherRequest)

	log.Lvl1(service.ServerIdentity(), "Owner. Received GetCipherRequest.")

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
		log.Error(service.ServerIdentity(), "Requested cipehrtext does not exist")
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
	log.Lvl2(service.ServerIdentity(), "Sending reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the owner's GetCipherReply.
// It simply sends the reply through the channel.
func (service *Service) processGetCipherReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetCipherReply)

	log.Lvl2(service.ServerIdentity(), "Received GetCipherReply:", reply.ReqID)

	// Simply send reply through channel
	service.getCipherRepLock.RLock()
	service.getCipherReplies[reply.ReqID] <- reply
	service.getCipherRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
