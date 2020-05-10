package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

// Delegates the sharing of the ciphertext indexed by its ID to its owner.
func (service *Service) DelegateShareCipher(sessionID messages.SessionID, cipherID messages.CipherID) (messages.SharesID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating sharing:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return NilSharesID
	if cipherID == messages.NilCipherID {
		err := errors.New("The inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilSharesID, err
	}

	// Create EncToSharesRequest with its ID
	reqID := messages.NewEncToSharesRequestID()
	req := &messages.EncToSharesRequest{reqID, sessionID, cipherID}

	// Create channel before sending request to root.
	service.encToSharesRepLock.Lock()
	service.encToSharesReplies[reqID] = make(chan *messages.EncToSharesReply)
	service.encToSharesRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending EncToSharesRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send EncToSharesRequest to owner: " + err.Error())
		log.Error(err)
		return messages.NilSharesID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply...")
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
		err := errors.New("Received invalid reply: owner couldn't perform EncToShares")
		log.Error(service.ServerIdentity(), err)

		return messages.NilSharesID, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.SharesID)

	return reply.SharesID, nil
}

// The EncToSharesRequest is received by the owner of the ciphertext.
func (service *Service) processEncToSharesRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.EncToSharesRequest)

	log.Lvl1(service.ServerIdentity(), "Received EncToSharesRequest for ciphertext", req.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.EncToSharesReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Share the ciphertext
	sharesID, err := service.shareCipher(req.SessionID, req.CipherID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not share the ciphertext:", err)
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.SharesID = sharesID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// Shares the ciphertext indexed by its ID.
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

// The EncToSharesReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateShareCipher is waiting.
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

// Legacy query
func (service *Service) HandleEncToSharesQuery(query *messages.EncToSharesQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received EncToSharesQuery for ciphertext:", query.CipherID)

	sharesID, err := service.shareCipher(query.SessionID, query.CipherID)
	return &messages.EncToSharesResponse{sharesID, err == nil}, err
}
