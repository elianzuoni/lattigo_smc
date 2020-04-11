package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleSharesToEncQuery(query *SharesToEncQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received SharesToEncQuery for shares:", query.SharesID)

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[query.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create SharesToEncRequest with its ID
	reqID := newSharesToEncRequestID()
	req := &SharesToEncRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.sharesToEncRepLock.Lock()
	s.sharesToEncReplies[reqID] = make(chan *SharesToEncReply)
	s.sharesToEncRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending SharesToEncRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send SharesToEncRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.sharesToEncRepLock.RLock()
	replyChan := s.sharesToEncReplies[reqID]
	s.sharesToEncRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.sharesToEncRepLock.Lock()
	close(replyChan)
	delete(s.sharesToEncReplies, reqID)
	s.sharesToEncRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform shares-to-enc")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")

	return &SharesToEncResponse{reply.NewCipherID, reply.Valid}, nil
}

func (smc *Service) processSharesToEncRequest(msg *network.Envelope) {
	req := (msg.Msg).(*SharesToEncRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received SharesToEncRequest.")

	// Start by declaring reply with minimal fields.
	reply := &SharesToEncReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[req.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Then, launch the shares-to-enc protocol to get the re-encrypted ciphertext
	log.Lvl2(smc.ServerIdentity(), "Re-encrypting ciphertext")
	ctReenc, err := smc.reencryptCiphertext(req.SessionID, req.Query.SharesID, req.Query.Seed)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not perform shares-to-enc:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Register in the local database
	newCipherID := newCipherID(smc.ServerIdentity())
	s.databaseLock.Lock()
	s.database[newCipherID] = ctReenc
	s.databaseLock.Unlock()

	log.Lvl3(smc.ServerIdentity(), "Successfully re-encrypted ciphertext")

	// Set fields in the reply
	reply.Valid = true
	reply.NewCipherID = newCipherID

	// Send the positive reply to the server
	log.Lvl2(smc.ServerIdentity(), "Replying (positively) to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (smc *Service) reencryptCiphertext(SessionID SessionID, SharesID SharesID, Seed []byte) (*bfv.Ciphertext, error) {
	log.Lvl2(smc.ServerIdentity(), "Re-encrypting a ciphertext")

	// Extract session
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, SharesToEncProtocolName)

	// Create configuration for the protocol instance
	config := &S2EConfig{SessionID, SharesID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating shares-to-enc protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate shares-to-enc protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering shares-to-enc protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	s2e := protocol.(*protocols.SharesToEncryptionProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting shares-to-enc protocol")
	err = s2e.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start shares-to-enc protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = s2e.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch shares-to-enc protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(s2e.ServerIdentity(), "Waiting for shares-to-enc protocol to terminate...")
	s2e.WaitDone()
	ctReenc := s2e.OutputCiphertext

	log.Lvl2(smc.ServerIdentity(), "Shared ciphertext!")

	return ctReenc, nil
}

func (smc *Service) processSharesToEncReply(msg *network.Envelope) {
	reply := (msg.Msg).(*SharesToEncReply)

	log.Lvl1(smc.ServerIdentity(), "Received SharesToEncReply")

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[reply.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.sharesToEncRepLock.RLock()
	s.sharesToEncReplies[reply.ReqID] <- reply
	s.sharesToEncRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
