package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleRetrieveQuery(query *RetrieveQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received RetrieveQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create RetrieveRequest with its ID
	reqID := newRetrieveRequestID()
	req := &RetrieveRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.retrieveReplies[reqID] = make(chan *RetrieveReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending RetrieveRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send RetrieveRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.retrieveReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform key-switch")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &RetrieveResponse{reply.Ciphertext, reply.Valid}, nil
}

func (smc *Service) processRetrieveRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RetrieveRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received RetrieveRequest.")

	// Start by declaring reply with minimal fields.
	reply := &RetrieveReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply:", err)
		}
		return
	}

	// Check existence of ciphertext
	ct, ok := s.database[req.Query.CipherID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, launch the public key-switching protocol to get the switched ciphertext
	log.Lvl2(smc.ServerIdentity(), "Switching ciphertext")
	ctSwitch, err := smc.switchCiphertext(req.SessionID, req.Query.PublicKey, ct)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not perform key-switching:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(smc.ServerIdentity(), "Successfully switched ciphertext")

	// Set fields in the reply
	reply.Ciphertext = ctSwitch
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

func (smc *Service) switchCiphertext(SessionID SessionID, pk *bfv.PublicKey, ct *bfv.Ciphertext) (*bfv.Ciphertext, error) {
	log.Lvl2(smc.ServerIdentity(), "Performing public key-switching")

	// Extract session
	s, ok := smc.sessions[SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.CollectivePublicKeySwitchingProtocolName)

	// Create configuration for the protocol instance
	config := &PublicSwitchConfig{SessionID, pk, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating PCKS protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate PCKS protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering PCKS protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting PCKS protocol")
	err = pcks.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start PCKS protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = pcks.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch PCKS protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(pcks.ServerIdentity(), "Waiting for PCKS protocol to terminate...")
	pcks.WaitDone()

	log.Lvl2(smc.ServerIdentity(), "Switched ciphertext!")

	return &pcks.CiphertextOut, nil
}

func (smc *Service) processRetrieveReply(msg *network.Envelope) {
	reply := (msg.Msg).(*RetrieveReply)

	log.Lvl1(smc.ServerIdentity(), "Received RetrieveReply")

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.retrieveReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
