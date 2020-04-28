package session

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (serv *Service) HandleGenRotKeyQuery(query *messages.GenRotKeyQuery) (network.Message, error) {
	log.Lvl1(serv.ServerIdentity(), "Received GenRotKeyQuery")

	// Extract Session, if existent
	s, ok := serv.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(serv.ServerIdentity(), err)
		return nil, err
	}

	// Create GenRotKeyRequest with its ID
	reqID := messages.NewGenRotKeyRequestID()
	req := &messages.GenRotKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.GenRotKeyRepLock.Lock()
	s.GenRotKeyReplies[reqID] = make(chan *messages.GenRotKeyReply)
	s.GenRotKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(serv.ServerIdentity(), "Sending GenRotKeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := serv.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send GenRotKeyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(serv.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.GenRotKeyRepLock.RLock()
	replyChan := s.GenRotKeyReplies[reqID]
	s.GenRotKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(serv.ServerIdentity(), "Received reply from channel. Closing it.")
	s.GenRotKeyRepLock.Lock()
	close(replyChan)
	delete(s.GenRotKeyReplies, reqID)
	s.GenRotKeyRepLock.Unlock()

	log.Lvl4(serv.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't generate public key")
		log.Error(serv.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	} else {
		log.Lvl4(serv.ServerIdentity(), "Received valid reply from channel")
	}

	return &messages.GenRotKeyResponse{reply.Valid}, nil
}

func (serv *Service) processGenRotKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GenRotKeyRequest)

	log.Lvl1(serv.ServerIdentity(), "Root. Received GenRotKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GenRotKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent (actually, only check existence)
	_, ok := serv.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(serv.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := serv.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Then, launch the genRotKey protocol to get the MasterRotlicKey
	log.Lvl2(serv.ServerIdentity(), "Generating Rotation Key")
	err := serv.genRotKey(req.Query.SessionID, req.Query.RotIdx, req.Query.K, req.Query.Seed)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not generate rotation key:", err)
		err := serv.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(serv.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(serv.ServerIdentity(), "Successfully generated rotlic key")

	// Set fields in the reply
	reply.Valid = true

	// Send the positive reply to the server
	log.Lvl2(serv.ServerIdentity(), "Replying (positively) to server")
	err = serv.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (serv *Service) genRotKey(SessionID messages.SessionID, rotIdx int, K uint64, Seed []byte) error {
	log.Lvl1(serv.ServerIdentity(), "Root. Generating EvaluationKey")

	// Extract session
	s, ok := serv.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(serv.ServerIdentity(), err)
		return err
	}

	// Lock the rotation key (no check for existence: can be overwritten)
	// We must hold the lock until the end, because only at the end is the RotKey generated.
	// We can do so, because no other lock will be is held by this goroutine, or by any other one waiting for
	// this or for which this waits.
	s.RotKeyLock.Lock()
	defer s.RotKeyLock.Unlock()

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, serv.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(serv.ServerIdentity(), err)
		return err
	}
	tni := serv.NewTreeNodeInstance(tree, tree.Root, protocols.RotationProtocolName)

	// Create configuration for the protocol instance
	config := &messages.GenRotKeyConfig{SessionID, rotIdx, K, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(serv.ServerIdentity(), "Instantiating RKG protocol")
	protocol, err := serv.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not instantiate RKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(serv.ServerIdentity(), "Registering RKG protocol instance")
	err = serv.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	rkgp := protocol.(*protocols.RotationKeyProtocol)

	// Start the protocol
	log.Lvl2(serv.ServerIdentity(), "Starting RKG protocol")
	err = rkgp.Start()
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not start RKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = rkgp.Dispatch()
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not dispatch RKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(rkgp.ServerIdentity(), "Waiting for RKG protocol to terminate...")
	rkgp.WaitDone()

	// Retrieve RotationKey
	s.RotationKey = &rkgp.RotKey
	log.Lvl1(serv.ServerIdentity(), "Generated RotationKey!")

	return nil
}

func (serv *Service) processGenRotKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GenRotKeyReply)

	log.Lvl1(serv.ServerIdentity(), "Received GenRotKeyReply")

	// Extract Session, if existent
	s, ok := serv.sessions.GetSession(reply.SessionID)
	if !ok {
		log.Error(serv.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.GenRotKeyRepLock.RLock()
	s.GenRotKeyReplies[reply.ReqID] <- reply
	s.GenRotKeyRepLock.RUnlock()
	log.Lvl4(serv.ServerIdentity(), "Sent reply through channel")

	return
}
