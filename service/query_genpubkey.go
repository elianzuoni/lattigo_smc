package service

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleGenPubKeyQuery(query *GenPubKeyQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received GenPubKeyQuery")

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[query.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create GenPubKeyRequest with its ID
	reqID := newGenPubKeyRequestID()
	req := &GenPubKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.genPubKeyRepLock.Lock()
	s.genPubKeyReplies[reqID] = make(chan *GenPubKeyReply)
	s.genPubKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending GenPubKeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send GenPubKeyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.genPubKeyRepLock.RLock()
	replyChan := s.genPubKeyReplies[reqID]
	s.genPubKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.genPubKeyRepLock.Lock()
	close(replyChan)
	delete(s.genPubKeyReplies, reqID)
	s.genPubKeyRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't generate public key")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	}

	return &GenPubKeyResponse{reply.MasterPublicKey, reply.Valid}, nil
}

func (smc *Service) processGenPubKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*GenPubKeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received GenPubKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &GenPubKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

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

	// Then, launch the genPublicKey protocol to get the MasterPublicKey
	log.Lvl2(smc.ServerIdentity(), "Generating Public Key")
	err := smc.genPublicKey(req.Query.SessionID, req.Query.Seed)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not generate public key:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(smc.ServerIdentity(), "Successfully generated public key")

	// Set fields in the reply
	reply.MasterPublicKey = s.MasterPublicKey // No need to lock pubKeyLock
	reply.Valid = true

	// Send the positive reply to the server
	log.Lvl2(smc.ServerIdentity(), "Replying (positively) to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (smc *Service) genPublicKey(SessionID SessionID, Seed []byte) error {
	log.Lvl1(smc.ServerIdentity(), "Root. Generating PublicKey")

	// Extract session
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Check that PubKey is not generated
	// We must hold the lock until the end, because only at the end the PubKey is generated
	// We can do so, because no other lock is held by this goroutine, or any other which waits for this
	// or for which this waits.
	s.pubKeyLock.Lock()
	defer s.pubKeyLock.Unlock()
	if s.MasterPublicKey != nil {
		err := errors.New("MasterPublicKey is already set")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveKeyGenerationProtocolName)

	// Create configuration for the protocol instance
	config := &GenPubKeyConfig{SessionID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating CKG protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate CKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering CKG protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting CKG protocol")
	err = ckgp.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start CKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ckgp.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch CKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ckgp.ServerIdentity(), "Waiting for CKG protocol to terminate...")
	ckgp.WaitDone()

	// Retrieve PublicKey
	s.MasterPublicKey = ckgp.Pk
	log.Lvl1(smc.ServerIdentity(), "Generated PublicKey!")

	return nil
}

func (smc *Service) processGenPubKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*GenPubKeyReply)

	log.Lvl1(smc.ServerIdentity(), "Received GenPubKeyReply")

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[reply.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.genPubKeyRepLock.RLock()
	s.genPubKeyReplies[reply.ReqID] <- reply
	s.genPubKeyRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
