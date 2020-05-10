package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

// Delegates the public key switch of the ciphertext indexed by the ID to its owner.
func (service *Service) DelegateSwitchCipher(sessionID messages.SessionID, cipherID messages.CipherID,
	publicKey *bfv.PublicKey) (*bfv.Ciphertext, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating public key switch:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return nil
	if cipherID == messages.NilCipherID {
		err := errors.New("The inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create SwitchRequest with its ID
	reqID := messages.NewSwitchRequestID()
	req := &messages.SwitchRequest{reqID, sessionID, cipherID, publicKey}

	// Create channel before sending request to root.
	service.switchRepLock.Lock()
	service.switchReplies[reqID] = make(chan *messages.SwitchReply)
	service.switchRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending SwitchRequest to owner of the ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send SwitchRequest to node: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply...")
	service.switchRepLock.RLock()
	replyChan := service.switchReplies[reqID]
	service.switchRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.switchRepLock.Lock()
	close(replyChan)
	delete(service.switchReplies, reqID)
	service.switchRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform public key switch")
		log.Error(service.ServerIdentity(), err)

		return nil, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")

	return reply.Ciphertext, nil
}

// The SwitchRequest is received by the owner of the ciphertext.
func (service *Service) processSwitchRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SwitchRequest)

	log.Lvl1(service.ServerIdentity(), "Received SwitchRequest for ciphertext:", req.CipherID)

	// Start by declaring reply with minimal fields
	reply := &messages.SwitchReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Re-encrypt the shares
	ct, err := service.switchCipher(req.SessionID, req.PublicKey, req.CipherID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not switch the ciphertext:", err)
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.Ciphertext = ct

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// Switches the ciphertext indexed by the ID.
func (service *Service) switchCipher(sessionID messages.SessionID, pk *bfv.PublicKey,
	cipherID messages.CipherID) (*bfv.Ciphertext, error) {
	log.Lvl2(service.ServerIdentity(), "Public-key-switching ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Perform the PublicKeySwitchProtocol to switch the ciphertext

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.CollectivePublicKeySwitchingProtocolName)

	// Create configuration for the protocol instance
	config := &messages.SwitchConfig{sessionID, pk, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating PCKS protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate PCKS protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering PCKS protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting PCKS protocol")
	err = pcks.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start PCKS protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = pcks.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch PCKS protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(pcks.ServerIdentity(), "Waiting for PCKS protocol to terminate...")
	pcks.WaitDone()

	log.Lvl2(service.ServerIdentity(), "Switched ciphertext!")

	// Done with the protocol

	// Do not store locally

	return &pcks.CiphertextOut, nil
}

// The SwitchReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateSwitchCipher is waiting.
func (service *Service) processSwitchReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SwitchReply)

	log.Lvl1(service.ServerIdentity(), "Received SwitchReply")

	// Simply send reply through channel
	service.switchRepLock.RLock()
	service.switchReplies[reply.ReqID] <- reply
	service.switchRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleRetrieveQuery(query *messages.SwitchQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SwitchQuery for ciphertext:", query.CipherID)

	switchedCipher, err := service.switchCipher(query.SessionID, query.PublicKey, query.CipherID)
	return &messages.SwitchResponse{switchedCipher, err == nil}, err
}
