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
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create GenEvalKeyRequest with its ID
	reqID := newGenEvalKeyRequestID()
	req := &GenEvalKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.genEvalKeyReplies[reqID] = make(chan *GenEvalKeyReply)

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
	reply := <-s.genEvalKeyReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &GenEvalKeyResponse{reply.Valid}, nil
}

func (smc *Service) processGenEvalKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*GenEvalKeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received GenEvalKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &GenEvalKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent (actually, only check existence)
	_, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Then, launch the genPublicKey protocol to get the MasterPublicKey
	log.Lvl2(smc.ServerIdentity(), "Generating Evaluation Key")
	err := smc.genEvalKey(req.Query.SessionID)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not generate evaluation key:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(smc.ServerIdentity(), "Successfully generated public key")

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

func (smc *Service) genEvalKey(SessionID SessionID) error {
	log.Lvl1(smc.ServerIdentity(), "Root. Generating EvaluationKey")

	// Extract session
	s, ok := smc.sessions[SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.RelinearizationKeyProtocolName)

	// Create configuration for the protocol instance
	config := &GenEvalKeyConfig{SessionID}
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

	// Retrieve PublicKey
	s.evalKey = ekgp.EvaluationKey
	log.Lvl1(smc.ServerIdentity(), "Generated EvaluationKey!")

	return nil
}

func (smc *Service) processGenEvalKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*GenEvalKeyReply)

	log.Lvl1(smc.ServerIdentity(), "Received GenEvalKeyReply")

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.genEvalKeyReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
