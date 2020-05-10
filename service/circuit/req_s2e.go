package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

// Delegates the re-encryption of the shares indexed by the ID to a random node.
// TODO: discuss this choice
func (service *Service) DelegateReencryptShares(sessionID messages.SessionID, sharesID messages.SharesID,
	seed []byte) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating re-encryption:", sharesID)

	// Check that the input is not NilSharesID: otherwise, return NilCipherID
	if sharesID == messages.NilSharesID {
		err := errors.New("The inputs is NilSharesID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create SharesToEncRequest with its ID
	reqID := messages.NewSharesToEncRequestID()
	req := &messages.SharesToEncRequest{reqID, sessionID, sharesID, seed}

	// Create channel before sending request to root.
	service.sharesToEncRepLock.Lock()
	service.sharesToEncReplies[reqID] = make(chan *messages.SharesToEncReply)
	service.sharesToEncRepLock.Unlock()

	// Send request to random node
	log.Lvl2(service.ServerIdentity(), "Sending SharesToEncRequest to random node:", reqID)
	err := service.SendRaw(s.Roster.RandomServerIdentity(), req)
	if err != nil {
		err = errors.New("Couldn't send SharesToEncRequest to node: " + err.Error())
		log.Error(err)
		return messages.NilCipherID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply...")
	service.sharesToEncRepLock.RLock()
	replyChan := service.sharesToEncReplies[reqID]
	service.sharesToEncRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.sharesToEncRepLock.Lock()
	close(replyChan)
	delete(service.sharesToEncReplies, reqID)
	service.sharesToEncRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform SharesToEnc")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The SharesToEncRequest is received by the owner of the ciphertext.
func (service *Service) processSharesToEncRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SharesToEncRequest)

	log.Lvl1(service.ServerIdentity(), "Received SharesToEncRequest for ciphertext", req.SharesID)

	// Start by declaring reply with minimal fields
	reply := &messages.SharesToEncReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Re-encrypt the shares
	cipherID, err := service.reencryptShares(req.SessionID, req.SharesID, req.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not re-encrypt the shares:", err)
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = cipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// Re-encrypts the shares indexed by the ID.
func (service *Service) reencryptShares(sessionID messages.SessionID, sharesID messages.SharesID,
	Seed []byte) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "Re-encrypting a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Perform the SharesToEncProtocol to re-encrypt the shares

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, SharesToEncProtocolName)

	// Create configuration for the protocol instance
	config := &messages.S2EConfig{sessionID, sharesID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return messages.NilCipherID, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating shares-to-enc protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate shares-to-enc protocol", err)
		return messages.NilCipherID, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering shares-to-enc protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return messages.NilCipherID, err
	}

	s2e := protocol.(*protocols.SharesToEncryptionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting shares-to-enc protocol")
	err = s2e.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start shares-to-enc protocol:", err)
		return messages.NilCipherID, err
	}
	// Call dispatch (the main logic)
	err = s2e.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch shares-to-enc protocol:", err)
		return messages.NilCipherID, err
	}

	// Wait for termination of protocol
	log.Lvl2(s2e.ServerIdentity(), "Waiting for shares-to-enc protocol to terminate...")
	s2e.WaitDone()

	log.Lvl2(service.ServerIdentity(), "Re-encrypted shares!")

	// Done with the protocol

	// Store locally
	newID := s.StoreCiphertextNewID(s2e.OutputCiphertext)

	return newID, nil
}

// The SharesToEncReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateReencryptShares is waiting.
func (service *Service) processSharesToEncReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SharesToEncReply)

	log.Lvl1(service.ServerIdentity(), "Received SharesToEncReply")

	// Simply send reply through channel
	service.sharesToEncRepLock.RLock()
	service.sharesToEncReplies[reply.ReqID] <- reply
	service.sharesToEncRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleSharesToEncQuery(query *messages.SharesToEncQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SharesToEncQuery for shares:", query.SharesID)

	newID, err := service.reencryptShares(query.SessionID, query.SharesID, query.Seed)
	return &messages.SharesToEncResponse{newID, err == nil}, err
}
