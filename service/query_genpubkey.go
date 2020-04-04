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
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create GenPubKeyRequest with its ID
	reqID := newGenPubKeyRequestID()
	req := GenPubKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.genPubKeyReplies[reqID] = make(chan *GenPubKeyReply)

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
	reply := <-s.genPubKeyReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &GenPubKeyResponse{reply.MasterPublicKey, reply.Valid}, nil
}

func (smc *Service) processGenPubKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*GenPubKeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received GenPubKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &GenPubKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	/*
		// Build preparation message to broadcast
		prep := GenPubKeyBroadcast{req.SessionID, req.ReqID,
			&E2SParameters{req.Query.CipherID, ct}}

		// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
		log.Lvl2(smc.ServerIdentity(), "Broadcasting preparation message to all nodes")
		err := utils.Broadcast(smc.ServiceProcessor, s.Roster, prep)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not broadcast preparation message:", err)
			err = smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
			if err != nil {
				log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
			}

			return
		}
	*/

	// Then, launch the genPublicKey protocol to get the MasterPublicKey
	log.Lvl2(smc.ServerIdentity(), "Generating Public Key")
	err := smc.genPublicKey(req.Query.SessionID)
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
	reply.MasterPublicKey = s.MasterPublicKey
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

/*
func (s *Service) processGenPubKeyBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received CreateSessionBroadcast")

	prep := msg.Msg.(*GenPubKeyBroadcast)

	// Send the enc-to-shares parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending genPubKey parameters through channel")
	s.genPubKeyParams <- prep.Params

	log.Lvl4(s.ServerIdentity(), "Sent genPubKey parameters through channel")

	return
}
*/

func (smc *Service) genPublicKey(SessionID SessionID) error {
	log.Lvl1(smc.ServerIdentity(), "Root. Generating PublicKey")

	// Extract session
	s, ok := smc.sessions[SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveKeyGenerationProtocolName)

	// Create configuration for the protocol instance
	config := &GenPubKeyConfig{SessionID}
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
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.genPubKeyReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
