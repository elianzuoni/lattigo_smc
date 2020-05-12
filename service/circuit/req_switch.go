package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
	"time"
)

// Handler for reception of SwitchQuery from client.
func (service *Service) HandleSwitchQuery(query *messages.SwitchQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SwitchQuery for ciphertext:", query.CipherID)

	switchedCipher, err := service.switchCipher("query", query.SessionID, query.PublicKey, query.CipherID)
	return &messages.SwitchResponse{switchedCipher, err == nil}, err
}

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
	var reply *messages.SwitchReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.SwitchReply, 1)
	service.switchRepLock.Lock()
	service.switchReplies[reqID] = replyChan
	service.switchRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending SwitchRequest to owner of the ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send SwitchRequest to node: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetSwitchRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.switchRepLock.Lock()
	close(replyChan)
	delete(service.switchReplies, reqID)
	service.switchRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform public key switch")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)

		return nil, err
	}

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received valid reply from channel")

	return reply.Ciphertext, nil
}

// The SwitchRequest is received by the owner of the ciphertext.
func (service *Service) processSwitchRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SwitchRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received SwitchRequest for ciphertext:", req.CipherID)

	// Start by declaring reply with minimal fields
	reply := &messages.SwitchReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Switch the ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to switch the ciphertext")
	ct, err := service.switchCipher(req.ReqID.String(), req.SessionID, req.PublicKey, req.CipherID)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not switch the ciphertext:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully switched the ciphertext")
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.Ciphertext = ct

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply (positively) to server:", err)
		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent positive reply to server")

	return
}

// Switches the ciphertext indexed by the ID.
// reqID is just a prefix for logs.
func (service *Service) switchCipher(reqID string, sessionID messages.SessionID, pk *bfv.PublicKey,
	cipherID messages.CipherID) (*bfv.Ciphertext, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Public-key-switch a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err
	}

	// Perform the PublicKeySwitchProtocol to switch the ciphertext

	// Create TreeNodeInstance as root
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Generating the Tree")
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.CollectivePublicKeySwitchingProtocolName)

	// Create configuration for the protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Creating the configuration")
	config := &messages.SwitchConfig{sessionID, pk, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Instantiating PCKS protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not instantiate PCKS protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Registering PCKS protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not register protocol instance:", err)
		return nil, err
	}

	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Starting PCKS protocol")
	err = pcks.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not start PCKS protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Dispatching protocol")
	err = pcks.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not dispatch PCKS protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(pcks.ServerIdentity(), "(ReqID =", reqID, ")\n", "Waiting for PCKS protocol to terminate...")
	pcks.WaitDone()

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Switched ciphertext!")

	// Done with the protocol

	// Do not store locally

	return &pcks.CiphertextOut, nil
}

// The SwitchReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateSwitchCipher is waiting.
func (service *Service) processSwitchReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SwitchReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received SwitchReply")

	// Get reply channel
	service.switchRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked SwitchRepLock")
	replyChan, ok := service.switchReplies[reply.ReqID]
	service.switchRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}
