package service

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleGenRotKeyQuery(query *GenRotKeyQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received GenRotKeyQuery")

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create GenRotKeyRequest with its ID
	reqID := newGenRotKeyRequestID()
	req := GenRotKeyRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.genRotKeyReplies[reqID] = make(chan *GenRotKeyReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending GenRotKeyRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send GenRotKeyRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.genRotKeyReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &GenRotKeyResponse{reply.Valid}, nil
}

func (smc *Service) processGenRotKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*GenRotKeyRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received GenRotKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &GenRotKeyReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

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

	/*
		// Build preparation message to broadcast
		prep := GenRotKeyBroadcast{req.SessionID, req.ReqID,
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
	log.Lvl2(smc.ServerIdentity(), "Generating Rotation Key")
	err := smc.genRotKey(req.Query.SessionID, req.Query.RotIdx, req.Query.K)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not generate rotation key:", err)
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

/*
func (s *Service) processGenRotKeyBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received CreateSessionBroadcast")

	prep := msg.Msg.(*GenRotKeyBroadcast)

	// Send the enc-to-shares parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending genRotKey parameters through channel")
	s.genRotKeyParams <- prep.Params

	log.Lvl4(s.ServerIdentity(), "Sent genRotKey parameters through channel")

	return
}
*/

func (smc *Service) genRotKey(SessionID SessionID, rotIdx int, K uint64) error {
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
	tni := smc.NewTreeNodeInstance(tree, tree.Root, protocols.RotationProtocolName)

	// Create configuration for the protocol instance
	config := &GenRotKeyConfig{SessionID, rotIdx, K}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating RKG protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate RKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering RKG protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	rkgp := protocol.(*protocols.RotationKeyProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting RKG protocol")
	err = rkgp.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start RKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = rkgp.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch RKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(rkgp.ServerIdentity(), "Waiting for RKG protocol to terminate...")
	rkgp.WaitDone()

	// Retrieve PublicKey
	s.rotationKey = &rkgp.RotKey
	log.Lvl1(smc.ServerIdentity(), "Generated RotationKey!")

	return nil
}

func (smc *Service) processGenRotKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*GenRotKeyReply)

	log.Lvl1(smc.ServerIdentity(), "Received GenRotKeyReply")

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.genRotKeyReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
