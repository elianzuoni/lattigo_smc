package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

// Delegates the refresh of the ciphertext indexed by its ID to its owner.
func (service *Service) DelegateRefreshCipher(sessionID messages.SessionID, cipherID messages.CipherID,
	seed []byte) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating refresh:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return NilCipherID
	if cipherID == messages.NilCipherID {
		err := errors.New("The inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create RefreshRequest with its ID
	reqID := messages.NewRefreshRequestID()
	req := &messages.RefreshRequest{reqID, sessionID, cipherID, seed}

	// Create channel before sending request to root.
	service.refreshRepLock.Lock()
	service.refreshReplies[reqID] = make(chan *messages.RefreshReply)
	service.refreshRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending RefreshRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send RefreshRequest to owner: " + err.Error())
		log.Error(err)
		return messages.NilCipherID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply...")
	service.refreshRepLock.RLock()
	replyChan := service.refreshReplies[reqID]
	service.refreshRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.refreshRepLock.Lock()
	close(replyChan)
	delete(service.refreshReplies, reqID)
	service.refreshRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform refresh")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The RefreshRequest is received by the owner of the ciphertext.
func (service *Service) processRefreshRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RefreshRequest)

	log.Lvl1(service.ServerIdentity(), "Received RefreshRequest for ciphertext", req.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.RefreshReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Refresh the ciphertext
	newCipherID, err := service.refreshCipher(req.SessionID, req.CipherID, req.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not refresh the ciphertext:", err)
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = newCipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// Refreshes the ciphertext indexed by its ID.
func (service *Service) refreshCipher(sessionID messages.SessionID, cipherID messages.CipherID,
	seed []byte) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "Refreshing ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Perform the RefreshProtocol to refresh the ciphertext

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveRefreshName)

	// Create configuration for the protocol instance
	config := &messages.RefreshConfig{sessionID, ct, seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return messages.NilCipherID, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating refresh protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate refresh protocol", err)
		return messages.NilCipherID, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering refresh protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register refresh protocol instance:", err)
		return messages.NilCipherID, err
	}

	refresh := protocol.(*protocols.RefreshProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting refresh protocol")
	err = refresh.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start refresh protocol:", err)
		return messages.NilCipherID, err
	}
	// Call dispatch (the main logic)
	err = refresh.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch refresh protocol:", err)
		return messages.NilCipherID, err
	}

	// Wait for termination of protocol
	log.Lvl2(refresh.ServerIdentity(), "Waiting for refresh protocol to terminate...")
	refresh.WaitDone()

	log.Lvl2(service.ServerIdentity(), "Refreshed ciphertext!")

	// Done with the protocol

	// Store locally
	refreshID := s.StoreCiphertextNewID(&refresh.Ciphertext)

	return refreshID, nil
}

// The RefreshReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateRefreshCipher is waiting.
func (service *Service) processRefreshReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RefreshReply)

	log.Lvl1(service.ServerIdentity(), "Received RefreshReply")

	// Simply send reply through channel
	service.refreshRepLock.RLock()
	service.refreshReplies[reply.ReqID] <- reply
	service.refreshRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleRefreshQuery(query *messages.RefreshQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received RefreshQuery for ciphertext:", query.CipherID)

	refreshID, err := service.refreshCipher(query.SessionID, query.CipherID, query.Seed)
	return &messages.RefreshResponse{refreshID, err == nil}, err
}
