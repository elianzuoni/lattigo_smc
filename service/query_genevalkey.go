package service

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleGenEvalKeyQuery(query *GenEvalKeyQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received GenEvalKeyQuery")

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[query.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create GenEvalKeyRequest with its ID
	reqID := newGenEvalKeyRequestID()
	req := &GenEvalKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.genEvalKeyRepLock.Lock()
	s.genEvalKeyReplies[reqID] = make(chan *GenEvalKeyReply)
	s.genEvalKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending GenEvalKeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send GenEvalKeyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.genEvalKeyRepLock.RLock()
	replyChan := s.genEvalKeyReplies[reqID]
	s.genEvalKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.genEvalKeyRepLock.Lock()
	close(replyChan)
	delete(s.genEvalKeyReplies, reqID)
	s.genEvalKeyRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't generate public key")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	}

	return &GenEvalKeyResponse{reply.Valid}, nil
}

func (smc *Service) processGenEvalKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*GenEvalKeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received GenEvalKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &GenEvalKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent (actually, only check existence)
	smc.sessionsLock.RLock()
	_, ok := smc.sessions[req.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Then, launch the genEvalKey protocol to get the MasterEvallicKey
	log.Lvl2(smc.ServerIdentity(), "Generating Evaluation Key")
	err := smc.genEvalKey(req.Query.SessionID, req.Query.Seed)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not generate evaluation key:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(smc.ServerIdentity(), "Successfully generated evallic key")

	// Set fields in the reply
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

func (smc *Service) genEvalKey(SessionID SessionID, Seed []byte) error {
	log.Lvl1(smc.ServerIdentity(), "Root. Generating EvaluationKey")

	// Extract session
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Check that EvalKey is not generated
	// We must hold the lock until the end, because only at the end the EvalKey is generated
	// We can do so, because no other lock is held by this goroutine, or any other which waits for this
	// or for which this waits.
	s.evalKeyLock.Lock()
	defer s.evalKeyLock.Unlock()
	if s.evalKey != nil {
		err := errors.New("Evaluation key is already set")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.RelinearizationKeyProtocolName)

	// Create configuration for the protocol instance
	config := &GenEvalKeyConfig{SessionID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating EKG protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate EKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering EKG protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ekgp := protocol.(*protocols.RelinearizationKeyProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting EKG protocol")
	err = ekgp.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start EKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ekgp.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch EKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ekgp.ServerIdentity(), "Waiting for EKG protocol to terminate...")
	ekgp.WaitDone()

	// Retrieve EvaluationKey
	s.evalKey = ekgp.EvaluationKey
	log.Lvl1(smc.ServerIdentity(), "Generated EvaluationKey!")

	return nil
}

func (smc *Service) processGenEvalKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*GenEvalKeyReply)

	log.Lvl1(smc.ServerIdentity(), "Received GenEvalKeyReply")

	// Extract Session, if existent
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[reply.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.genEvalKeyRepLock.RLock()
	s.genEvalKeyReplies[reply.ReqID] <- reply
	s.genEvalKeyRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
