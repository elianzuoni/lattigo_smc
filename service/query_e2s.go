package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (smc *Service) HandleEncToSharesQuery(query *messages.EncToSharesQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received EncToSharesQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create EncToSharesRequest with its ID
	reqID := messages.NewEncToSharesRequestID()
	req := &messages.EncToSharesRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.EncToSharesRepLock.Lock()
	s.EncToSharesReplies[reqID] = make(chan *messages.EncToSharesReply)
	s.EncToSharesRepLock.Unlock()

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
	s.EncToSharesRepLock.RLock()
	replyChan := s.EncToSharesReplies[reqID]
	s.EncToSharesRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	s.EncToSharesRepLock.Lock()
	close(replyChan)
	delete(s.EncToSharesReplies, reqID)
	s.EncToSharesRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")

	return &messages.EncToSharesResponse{reply.SharesID, reply.Valid}, nil
}

func (smc *Service) processEncToSharesRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.EncToSharesRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received EncToSharesRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.EncToSharesReply{SessionID: req.SessionID, ReqID: req.ReqID, SharesID: messages.NilSharesID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply:", err)
		}
		return
	}

	// Check existence of ciphertext
	ct, ok := s.GetCiphertext(req.Query.CipherID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Generate new SharesID
	sharesID := messages.NewSharesID()

	// Then, launch the enc-to-shares protocol to get the shared ciphertext
	log.Lvl2(smc.ServerIdentity(), "Sharing ciphertext")
	err := smc.shareCiphertext(req.SessionID, sharesID, ct)
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
	reply.SharesID = sharesID

	// Send the positive reply to the server
	log.Lvl2(smc.ServerIdentity(), "Replying (positively) to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (smc *Service) shareCiphertext(SessionID messages.SessionID, SharesID messages.SharesID, ct *bfv.Ciphertext) error {
	log.Lvl2(smc.ServerIdentity(), "Sharing a ciphertext")

	// Extract session
	s, ok := smc.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateNaryTreeWithRoot(2, smc.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(smc.ServerIdentity(), err)
		return err
	}
	tni := smc.NewTreeNodeInstance(tree, tree.Root, EncToSharesProtocolName)

	// Create configuration for the protocol instance
	config := &messages.E2SConfig{SessionID, SharesID, ct}
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
	reply := (msg.Msg).(*messages.EncToSharesReply)

	log.Lvl1(smc.ServerIdentity(), "Received EncToSharesReply")

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(reply.SessionID)
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.EncToSharesRepLock.RLock()
	s.EncToSharesReplies[reply.ReqID] <- reply
	s.EncToSharesRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
