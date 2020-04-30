package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

// Legacy query
func (service *Service) HandleEncToSharesQuery(query *messages.EncToSharesQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received EncToSharesQuery for ciphertext:", query.CipherID)

	/*
		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(query.SessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Create EncToSharesRequest with its ID
		reqID := messages.NewEncToSharesRequestID()
		req := &messages.EncToSharesRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.encToSharesRepLock.Lock()
		service.encToSharesReplies[reqID] = make(chan *messages.EncToSharesReply)
		service.encToSharesRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending EncToSharesRequest to root:", reqID)
		tree := s.Roster.GenerateBinaryTree()
		err := service.SendRaw(tree.Root.ServerIdentity, req)
		if err != nil {
			err = errors.New("Couldn't send EncToSharesRequest to root: " + err.Error())
			log.Error(err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
		service.encToSharesRepLock.RLock()
		replyChan := service.encToSharesReplies[reqID]
		service.encToSharesRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.encToSharesRepLock.Lock()
		close(replyChan)
		delete(service.encToSharesReplies, reqID)
		service.encToSharesRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel")

		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't perform enc-to-shares")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		}
		log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")

		return &messages.EncToSharesResponse{reply.SharesID, reply.Valid}, nil

	*/

	sharesID, err := service.shareCipher(query.SessionID, query.CipherID)
	return &messages.EncToSharesResponse{sharesID, err == nil}, err
}

func (service *Service) shareCipher(sessionID messages.SessionID, cipherID messages.CipherID) (messages.SharesID, error) {
	log.Lvl2(service.ServerIdentity(), "Sharing a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilSharesID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilSharesID, err
	}

	// Pick new SharesID, which will be the same at all nodes
	sharesID := messages.NewSharesID()

	// Perform the EncToSharesProtocol to share the ciphertext

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return messages.NilSharesID, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, EncToSharesProtocolName)

	// Create configuration for the protocol instance
	config := &messages.E2SConfig{sessionID, sharesID, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return messages.NilSharesID, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating enc-to-shares protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate enc-to-shares protocol", err)
		return messages.NilSharesID, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering enc-to-shares protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return messages.NilSharesID, err
	}

	e2s := protocol.(*protocols.EncryptionToSharesProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting enc-to-shares protocol")
	err = e2s.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return messages.NilSharesID, err
	}
	// Call dispatch (the main logic)
	err = e2s.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return messages.NilSharesID, err
	}

	// Wait for termination of protocol
	log.Lvl2(e2s.ServerIdentity(), "Waiting for enc-to-shares protocol to terminate...")
	e2s.WaitDone()

	log.Lvl2(service.ServerIdentity(), "Shared ciphertext!")

	// Done with the protocol

	// At this point, the protocol finaliser has already registered the share in the shares database

	return sharesID, nil
}

// To be modified

func (service *Service) processEncToSharesRequest(msg *network.Envelope) {
	/*
		req := (msg.Msg).(*messages.EncToSharesRequest)

		log.Lvl1(service.ServerIdentity(), "Root. Received EncToSharesRequest.")

		// Start by declaring reply with minimal fields.
		reply := &messages.EncToSharesReply{SessionID: req.SessionID, ReqID: req.ReqID, SharesID: messages.NilSharesID, Valid: false}

		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(req.SessionID)
		if !ok {
			log.Error(service.ServerIdentity(), "Requested session does not exist")
			// Send negative response
			err := service.SendRaw(msg.ServerIdentity, reply)
			if err != nil {
				log.Error("Could not send reply:", err)
			}
			return
		}

		// Check existence of ciphertext
		ct, ok := s.GetCiphertext(req.Query.CipherID)
		if !ok {
			log.Error(service.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
			err := service.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
			if err != nil {
				log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
			}

			return
		}

		// Generate new SharesID
		sharesID := messages.NewSharesID()

		// Then, launch the enc-to-shares protocol to get the shared ciphertext
		log.Lvl2(service.ServerIdentity(), "Sharing ciphertext")
		err := service.shareCiphertext(req.SessionID, sharesID, ct)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not perform enc-to-shares:", err)
			err := service.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
			if err != nil {
				log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
			}
			return
		}

		// The protocol finaliser has already registered the share in the shares database.

		log.Lvl3(service.ServerIdentity(), "Successfully shared ciphertext")

		// Set fields in the reply
		reply.Valid = true
		reply.SharesID = sharesID

		// Send the positive reply to the server
		log.Lvl2(service.ServerIdentity(), "Replying (positively) to server")
		err = service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (positively) to server")
			return
		}

		return

	*/
}

func (service *Service) processEncToSharesReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.EncToSharesReply)

	log.Lvl1(service.ServerIdentity(), "Received EncToSharesReply")

	// Simply send reply through channel
	service.encToSharesRepLock.RLock()
	service.encToSharesReplies[reply.ReqID] <- reply
	service.encToSharesRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
