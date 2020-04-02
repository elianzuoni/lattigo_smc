package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

func (s *Service) HandleEncToSharesQuery(query *EncToSharesQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received EncToSharesQuery for ciphertext:", query.CipherID)

	// Create EncToSharesRequest with its ID
	reqID := newEncToSharesRequestID()
	req := EncToSharesRequest{reqID, query}

	// Create channel before sending request to root.
	s.encToSharesReplies[reqID] = make(chan *EncToSharesReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending EncToSharesRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send EncToSharesRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.encToSharesReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &EncToSharesResponse{reply.Valid}, nil
}

func (s *Service) processEncToSharesRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received EncToSharesRequest.")

	req := (msg.Msg).(*EncToSharesRequest)
	reply := EncToSharesReply{ReqID: req.ReqID}

	// Check existence of ciphertext
	ct, ok := s.database[req.Query.CipherID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Build preparation message to broadcast
	prep := EncToSharesBroadcast{req.ReqID,
		&E2SParameters{req.Query.CipherID, ct}}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	err := utils.Broadcast(s.ServiceProcessor, s.Roster, prep)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not broadcast preparation message:", err)
		err = s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, launch the enc-to-shares protocol to get the shared ciphertext
	log.Lvl2(s.ServerIdentity(), "Sharing ciphertext")
	err = s.shareCiphertext()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not perform enc-to-shares:", err)
		err := s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// The protocol finaliser has already registered the share in the shares database.

	log.Lvl3(s.ServerIdentity(), "Successfully shared ciphertext")

	// Set fields in the reply
	reply.Valid = true

	// Send the positive reply to the server
	log.Lvl2(s.ServerIdentity(), "Replying (positively) to server")
	err = s.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (s *Service) processEncToSharesBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*EncToSharesBroadcast)

	// Send the enc-to-shares parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending encToShares parameters through channel")
	s.encToSharesParams <- prep.Params

	log.Lvl4(s.ServerIdentity(), "Sent encToShares parameters through channel")

	return
}

func (s *Service) shareCiphertext() error {
	log.Lvl2(s.ServerIdentity(), "Sharing a ciphertext")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating enc-to-shares protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, EncToSharesProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate enc-to-shares protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering enc-to-shares protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	e2s := protocol.(*protocols.EncryptionToSharesProtocol)

	// Start the protocol
	log.Lvl2(s.ServerIdentity(), "Starting enc-to-shares protocol")
	err = e2s.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = e2s.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(e2s.ServerIdentity(), "Waiting for enc-to-shares protocol to terminate...")
	e2s.WaitDone()
	// At this point, the protocol finaliser has already registered the share in the shares database

	log.Lvl2(s.ServerIdentity(), "Shared ciphertext!")

	return nil
}

func (s *Service) processEncToSharesReply(msg *network.Envelope) {
	reply := (msg.Msg).(*EncToSharesReply)

	log.Lvl1(s.ServerIdentity(), "Received EncToSharesReply")

	// Simply send reply through channel
	s.encToSharesReplies[reply.ReqID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
