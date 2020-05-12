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
	var reply *messages.SharesToEncReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.SharesToEncReply, 1)
	service.sharesToEncRepLock.Lock()
	service.sharesToEncReplies[reqID] = replyChan
	service.sharesToEncRepLock.Unlock()

	// Send request to random node
	log.Lvl2(service.ServerIdentity(), "Sending SharesToEncRequest to random node:", reqID)
	err := service.SendRaw(s.Roster.RandomServerIdentity(), req)
	if err != nil {
		err = errors.New("Couldn't send SharesToEncRequest to node: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetSharesToEncRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.sharesToEncRepLock.Lock()
	close(replyChan)
	delete(service.sharesToEncReplies, reqID)
	service.sharesToEncRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform SharesToEnc")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl3(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The SharesToEncRequest is received by the owner of the ciphertext.
func (service *Service) processSharesToEncRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SharesToEncRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received SharesToEncRequest for ciphertext", req.SharesID)

	// Start by declaring reply with minimal fields
	reply := &messages.SharesToEncReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Re-encrypt the shares
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to re-encrypt the shares")
	cipherID, err := service.reencryptShares(req.ReqID.String(), req.SessionID, req.SharesID, req.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not re-encrypt the shares:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully re-encrypted the shares")
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = cipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent reply to server")

	return
}

// Re-encrypts the shares indexed by the ID.
// reqID is just a prefix for logs.
func (service *Service) reencryptShares(reqID string, sessionID messages.SessionID, sharesID messages.SharesID,
	Seed []byte) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Re-encrypting a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Perform the SharesToEncProtocol to re-encrypt the shares

	// Create TreeNodeInstance as root
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Generating the Tree")
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, SharesToEncProtocolName)

	// Create configuration for the protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Creating the configuration")
	config := &messages.S2EConfig{sessionID, sharesID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return messages.NilCipherID, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Instantiating shares-to-enc protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not instantiate shares-to-enc protocol", err)
		return messages.NilCipherID, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Registering shares-to-enc protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not register protocol instance:", err)
		return messages.NilCipherID, err
	}

	s2e := protocol.(*protocols.SharesToEncryptionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Starting shares-to-enc protocol")
	err = s2e.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not start shares-to-enc protocol:", err)
		return messages.NilCipherID, err
	}
	// Call dispatch (the main logic)
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Dispatching protocol")
	err = s2e.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not dispatch shares-to-enc protocol:", err)
		return messages.NilCipherID, err
	}

	// Wait for termination of protocol
	log.Lvl2(s2e.ServerIdentity(), "(ReqID =", reqID, ")\n", "Waiting for shares-to-enc protocol to terminate...")
	s2e.WaitDone()

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Re-encrypted shares!")

	// Done with the protocol

	// Store locally
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Storing the result")
	newID := s.StoreCiphertextNewID(s2e.OutputCiphertext)

	return newID, nil
}

// The SharesToEncReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateReencryptShares is waiting.
func (service *Service) processSharesToEncReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SharesToEncReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received SharesToEncReply")

	// Get reply channel
	service.sharesToEncRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked SharesToEncRepLock")
	replyChan, ok := service.sharesToEncReplies[reply.ReqID]
	service.sharesToEncRepLock.RUnlock()

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
func (service *Service) HandleSharesToEncQuery(query *messages.SharesToEncQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SharesToEncQuery for shares:", query.SharesID)

	newID, err := service.reencryptShares("query", query.SessionID, query.SharesID, query.Seed)
	return &messages.SharesToEncResponse{newID, err == nil}, err
}
