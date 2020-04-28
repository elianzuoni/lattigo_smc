package session

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleGenEvalKeyQuery(query *messages.GenEvalKeyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received GenEvalKeyQuery")

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create GenEvalKeyRequest with its ID
	reqID := messages.NewGenEvalKeyRequestID()
	req := &messages.GenEvalKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	service.genEvalKeyRepLock.Lock()
	service.genEvalKeyReplies[reqID] = make(chan *messages.GenEvalKeyReply)
	service.genEvalKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GenEvalKeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := service.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send GenEvalKeyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	service.genEvalKeyRepLock.RLock()
	replyChan := service.genEvalKeyReplies[reqID]
	service.genEvalKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.genEvalKeyRepLock.Lock()
	close(replyChan)
	delete(service.genEvalKeyReplies, reqID)
	service.genEvalKeyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't generate public key")
		log.Error(service.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")
	}

	return &messages.GenEvalKeyResponse{reply.Valid}, nil
}

func (service *Service) processGenEvalKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GenEvalKeyRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received GenEvalKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GenEvalKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent (actually, only check existence)
	_, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := service.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Then, launch the genEvalKey protocol to get the MasterEvallicKey
	log.Lvl2(service.ServerIdentity(), "Generating Evaluation Key")
	err := service.genEvalKey(req.Query.SessionID, req.Query.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not generate evaluation key:", err)
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(service.ServerIdentity(), "Successfully generated evallic key")

	// Set fields in the reply
	reply.Valid = true

	// Send the positive reply to the server
	log.Lvl2(service.ServerIdentity(), "Replying (positively) to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (service *Service) genEvalKey(SessionID messages.SessionID, Seed []byte) error {
	log.Lvl1(service.ServerIdentity(), "Root. Generating EvaluationKey")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Check that EvalKey is not generated
	// We must hold the lock until the end, because only at the end the EvalKey is generated
	// We can do so, because no other lock is held by this goroutine, or any other which waits for this
	// or for which this waits.
	s.EvalKeyLock.Lock()
	defer s.EvalKeyLock.Unlock()
	if s.EvalKey != nil {
		err := errors.New("Evaluation key is already set")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.RelinearizationKeyProtocolName)

	// Create configuration for the protocol instance
	config := &messages.GenEvalKeyConfig{SessionID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating EKG protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate EKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering EKG protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ekgp := protocol.(*protocols.RelinearizationKeyProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting EKG protocol")
	err = ekgp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start EKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ekgp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch EKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ekgp.ServerIdentity(), "Waiting for EKG protocol to terminate...")
	ekgp.WaitDone()

	// Retrieve EvaluationKey
	s.EvalKey = ekgp.EvaluationKey
	log.Lvl1(service.ServerIdentity(), "Generated EvaluationKey!")

	return nil
}

func (service *Service) processGenEvalKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GenEvalKeyReply)

	log.Lvl1(service.ServerIdentity(), "Received GenEvalKeyReply")

	// Simply send reply through channel
	service.genEvalKeyRepLock.RLock()
	service.genEvalKeyReplies[reply.ReqID] <- reply
	service.genEvalKeyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
