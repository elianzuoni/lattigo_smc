package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
	"time"
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
	var reply *messages.EncToSharesReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.EncToSharesReply, 1)
	service.encToSharesRepLock.Lock()
	service.encToSharesReplies[reqID] = replyChan
	service.encToSharesRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending EncToSharesRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send EncToSharesRequest to owner: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilSharesID, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetEncToSharesRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilSharesID, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.encToSharesRepLock.Lock()
	close(replyChan)
	delete(service.encToSharesReplies, reqID)
	service.encToSharesRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform EncToShares")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)

		return messages.NilSharesID, err
	}

	log.Lvl4(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received valid reply from channel:", reply.SharesID)

	return reply.SharesID, nil
}

// The EncToSharesRequest is received by the owner of the ciphertext.
func (service *Service) processEncToSharesRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.EncToSharesRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received EncToSharesRequest for ciphertext", req.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.EncToSharesReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Share the ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to share the ciphertext")
	sharesID, err := service.shareCipher(req.ReqID.String(), req.SessionID, req.CipherID)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not share the ciphertext:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully shared the ciphertext")
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.SharesID = sharesID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
		return
	}
	log.Lvl4(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent reply to server")

	return
}

// Shares the ciphertext indexed by its ID.
// reqID is just a prefix for logs.
func (service *Service) shareCipher(reqID string, sessionID messages.SessionID,
	cipherID messages.CipherID) (messages.SharesID, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Share a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilSharesID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilSharesID, err
	}

	// Pick new SharesID, which will be the same at all nodes
	sharesID := messages.NewSharesID()

	// Perform the EncToSharesProtocol to share the ciphertext

	// Create configuration for the protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Creating the configuration")
	config := &messages.E2SConfig{sessionID, sharesID, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", "Could not marshal protocol configuration:", err)
		return messages.NilSharesID, err
	}
	conf := onet.GenericConfig{data}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", err)
		return messages.NilSharesID, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, EncToSharesProtocolName)
	err = tni.SetConfig(&conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", "Could not set config:", err)
		return messages.NilSharesID, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", "Instantiating protocol")
	protocol, err := service.NewProtocol(tni, &conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol", err)
		return messages.NilSharesID, err
	}

	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Registering enc-to-shares protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not register protocol instance:", err)
		return messages.NilSharesID, err
	}

	e2s := protocol.(*protocols.EncryptionToSharesProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Starting enc-to-shares protocol")
	err = e2s.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not start enc-to-shares protocol:", err)
		return messages.NilSharesID, err
	}
	// Call dispatch (the main logic)
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Dispatching protocol")
	err = e2s.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not dispatch enc-to-shares protocol:", err)
		return messages.NilSharesID, err
	}

	// Wait for termination of protocol
	log.Lvl2(e2s.ServerIdentity(), "(ReqID =", reqID, ")\n", "Waiting for enc-to-shares protocol to terminate...")
	e2s.WaitDone()

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Shared ciphertext!")

	// Done with the protocol

	// At this point, the protocol finaliser has already registered the share in the shares database

	return sharesID, nil
}

// The EncToSharesReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateShareCipher is waiting.
func (service *Service) processEncToSharesReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.EncToSharesReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received EncToSharesReply")

	// Get reply channel
	service.encToSharesRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked EncToSharesRepLock")
	replyChan, ok := service.encToSharesReplies[reply.ReqID]
	service.encToSharesRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleEncToSharesQuery(query *messages.EncToSharesQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received EncToSharesQuery for ciphertext:", query.CipherID)

	sharesID, err := service.shareCipher("query", query.SessionID, query.CipherID)
	return &messages.EncToSharesResponse{sharesID, err == nil}, err
}
