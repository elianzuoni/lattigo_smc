package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (smc *Service) HandleRefreshQuery(query *messages.RefreshQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received RefreshQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create RefreshRequest with its ID
	reqID := messages.NewRefreshRequestID()
	req := &messages.RefreshRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.RefreshRepLock.Lock()
	s.RefreshReplies[reqID] = make(chan *messages.RefreshReply)
	s.RefreshRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending RefreshRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send RefreshRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.RefreshRepLock.RLock()
	replyChan := s.RefreshReplies[reqID]
	s.RefreshRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.RefreshRepLock.Lock()
	close(replyChan)
	delete(s.RefreshReplies, reqID)
	s.RefreshRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform refresh")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")

	return &messages.RefreshResponse{reply.NewCipherID, reply.Valid}, nil
}

func (smc *Service) processRefreshRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RefreshRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received RefreshRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.RefreshReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply:", err)
		}
		return
	}

	// Check existence of ciphertext
	ct, ok := s.GetCiphertext(req.Query.CipherID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, launch the refresh protocol to get the refreshed ciphertext
	log.Lvl2(smc.ServerIdentity(), "Refreshing ciphertext")
	ctRefresh, err := smc.refreshCiphertext(req.Query.SessionID, ct, req.Query.Seed)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not perform refresh:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Register in the local database
	newCipherID := messages.NewCipherID(smc.ServerIdentity())
	s.StoreCiphertext(newCipherID, ctRefresh)

	log.Lvl3(smc.ServerIdentity(), "Successfully refreshed ciphertext")

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

func (smc *Service) refreshCiphertext(SessionID messages.SessionID, ct *bfv.Ciphertext, Seed []byte) (*bfv.Ciphertext, error) {
	log.Lvl2(smc.ServerIdentity(), "Performing refresh")

	// Extract session
	s, ok := smc.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateNaryTreeWithRoot(2, smc.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveRefreshName)

	// Create configuration for the protocol instance
	config := &messages.RefreshConfig{SessionID, ct, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating refresh protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate refresh protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering refresh protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register refresh protocol instance:", err)
		return nil, err
	}

	refresh := protocol.(*protocols.RefreshProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting refresh protocol")
	err = refresh.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start refresh protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = refresh.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch refresh protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(refresh.ServerIdentity(), "Waiting for refresh protocol to terminate...")
	refresh.WaitDone()

	log.Lvl2(smc.ServerIdentity(), "Refreshed ciphertext!")

	return &refresh.Ciphertext, nil
}

func (smc *Service) processRefreshReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RefreshReply)

	log.Lvl1(smc.ServerIdentity(), "Received RefreshReply")

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(reply.SessionID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.RefreshRepLock.RLock()
	s.RefreshReplies[reply.ReqID] <- reply
	s.RefreshRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
