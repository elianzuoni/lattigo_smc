package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (serv *Service) RetrieveRemoteCiphertext(SessionID messages.SessionID, CipherID messages.CipherID) (*bfv.Ciphertext, bool) {
	log.Lvl1(serv.ServerIdentity(), "Retrieving remote ciphertext")

	// Create CloseSessionRequest with its ID
	reqID := messages.NewGetCipherRequestID()
	serv.getCipherRepLock.Lock()
	req := &messages.GetCipherRequest{reqID, SessionID, CipherID}
	serv.getCipherRepLock.Unlock()

	// Create channel before sending request to root.
	serv.getCipherReplies[reqID] = make(chan *messages.GetCipherReply)

	// Send request to owner
	log.Lvl2(serv.ServerIdentity(), "Sending GetCipherRequest to ciphertext owner")
	err := serv.SendRaw(CipherID.GetServerIdentityOwner(), req)
	if err != nil {
		log.Error("Couldn't send GetCipherRequest to owner:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(serv.ServerIdentity(), "Sent GetCipherRequest to root. Waiting on channel to receive reply...")
	serv.getCipherRepLock.RLock()
	replyChan := serv.getCipherReplies[reqID]
	serv.getCipherRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(serv.ServerIdentity(), "Received reply from channel. Closing it.")
	serv.getCipherRepLock.Lock()
	close(replyChan)
	delete(serv.getCipherReplies, reqID)
	serv.getCipherRepLock.Unlock()

	log.Lvl4(serv.ServerIdentity(), "Closed channel, returning")

	return reply.Ciphertext, reply.Valid
}

func (serv *Service) processGetCipherRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetCipherRequest)

	log.Lvl1(serv.ServerIdentity(), "Owner. Received GetCipherRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetCipherReply{req.ReqID, nil, false}

	// Retrieve session
	s, ok := serv.GetSession(req.SessionID)
	if !ok {
		log.Error(serv.ServerIdentity(), "Requested session does not exist")
		err := serv.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(serv.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Retrieve ciphertext
	ct, ok := s.GetCiphertext(req.CipherID)
	if !ok {
		log.Error(serv.ServerIdentity(), "Requested cipehrtext does not exist")
		err := serv.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(serv.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Set fields in reply
	reply.Ciphertext = ct
	reply.Valid = true

	// Send reply to server
	log.Lvl2(serv.ServerIdentity(), "Sending reply to server")
	err := serv.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
	}
	log.Lvl4(serv.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the owner's GetCipherReply.
// It simply sends the reply through the channel.
func (serv *Service) processGetCipherReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetCipherReply)

	log.Lvl2(serv.ServerIdentity(), "Received GetCipherReply:", reply.ReqID)

	// Simply send reply through channel
	serv.getCipherRepLock.RLock()
	serv.getCipherReplies[reply.ReqID] <- reply
	serv.getCipherRepLock.RUnlock()
	log.Lvl4(serv.ServerIdentity(), "Sent reply through channel")

	return
}
