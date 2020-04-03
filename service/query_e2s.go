package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleEncToSharesQuery(query *EncToSharesQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received EncToSharesQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create EncToSharesRequest with its ID
	reqID := newEncToSharesRequestID()
	req := EncToSharesRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.encToSharesReplies[reqID] = make(chan *EncToSharesReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending EncToSharesRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send EncToSharesRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.encToSharesReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &EncToSharesResponse{reply.Valid}, nil
}

func (smc *Service) processEncToSharesRequest(msg *network.Envelope) {
	req := (msg.Msg).(*EncToSharesRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received EncToSharesRequest.")

	// Start by declaring reply with minimal fields.
	reply := &EncToSharesReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

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

	// Check existence of ciphertext
	ct, ok := s.database[req.Query.CipherID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	/*
		// Build preparation message to broadcast
		prep := EncToSharesBroadcast{req.SessionID, req.ReqID,
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

	// Then, launch the enc-to-shares protocol to get the shared ciphertext
	log.Lvl2(smc.ServerIdentity(), "Sharing ciphertext")
	err := smc.shareCiphertext(req.SessionID, req.Query.CipherID, ct)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not perform enc-to-shares:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// The protocol finaliser has already registered the share in the shares database.

	log.Lvl3(smc.ServerIdentity(), "Successfully shared ciphertext")

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
func (s *Service) processEncToSharesBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*EncToSharesBroadcast)

	// Send the enc-to-shares parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending encToShares parameters through channel")
	s.encToSharesParams <- prep.Params

	log.Lvl4(s.ServerIdentity(), "Sent encToShares parameters through channel")

	return
}
*/

func (smc *Service) shareCiphertext(SessionID SessionID, CipherID CipherID, ct *bfv.Ciphertext) error {
	log.Lvl2(smc.ServerIdentity(), "Sharing a ciphertext")

	// Extract session
	s, _ := smc.sessions[SessionID] // If we got to this point, surely the Session must exist

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, EncToSharesProtocolName)

	// Create configuration for the protocol instance
	config := &E2SConfig{SessionID, CipherID, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating enc-to-shares protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate enc-to-shares protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering enc-to-shares protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	e2s := protocol.(*protocols.EncryptionToSharesProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting enc-to-shares protocol")
	err = e2s.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = e2s.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(e2s.ServerIdentity(), "Waiting for enc-to-shares protocol to terminate...")
	e2s.WaitDone()
	// At this point, the protocol finaliser has already registered the share in the shares database

	log.Lvl2(smc.ServerIdentity(), "Shared ciphertext!")

	return nil
}

func (smc *Service) processEncToSharesReply(msg *network.Envelope) {
	reply := (msg.Msg).(*EncToSharesReply)

	log.Lvl1(smc.ServerIdentity(), "Received EncToSharesReply")

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.encToSharesReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
