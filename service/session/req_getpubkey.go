package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) GetRemotePublicKey(sessionID messages.SessionID) (*bfv.PublicKey, bool) {
	log.Lvl2(service.ServerIdentity(), "Retrieving remote public key")

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(sessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		return nil, false
	}

	// Create GetPubKeyRequest with its ID
	reqID := messages.NewGetPubKeyRequestID()
	req := &messages.GetPubKeyRequest{reqID, sessionID}

	// Create channel before sending request to root.
	service.getPubKeyRepLock.Lock()
	service.getPubKeyReplies[reqID] = make(chan *messages.GetPubKeyReply)
	service.getPubKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GetPubKeyRequest to root")
	err := service.SendRaw(s.Root, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "Couldn't send GetPubKeyRequest to root:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetPubKeyRequest to root. Waiting on channel to receive reply...")
	service.getPubKeyRepLock.RLock()
	replyChan := service.getPubKeyReplies[reqID]
	service.getPubKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.getPubKeyRepLock.Lock()
	close(replyChan)
	delete(service.getPubKeyReplies, reqID)
	service.getPubKeyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

	return reply.PublicKey, reply.Valid
}

func (service *Service) processGetPubKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetPubKeyRequest)

	log.Lvl2(service.ServerIdentity(), "Root. Received GetPubKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetPubKeyReply{req.ReqID, nil, false}

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Get Public Key
	s.pubKeyLock.RLock()
	pk := s.publicKey
	s.pubKeyLock.RUnlock()

	// Check existence
	if pk == nil {
		log.Error(service.ServerIdentity(), "Public key not generated")
		reply.PublicKey = nil
		reply.Valid = false
	} else {
		reply.PublicKey = pk
		reply.Valid = false
	}

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
		return
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

/*
func (service *Service) closeSession(SessionID messages.SessionID) error {
	log.Lvl2(service.ServerIdentity(), "Closing a session")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, CloseSessionProtocolName)

	// Create configuration for the protocol instance
	config := &messages.CloseSessionConfig{SessionID}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating close-session protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate create-session protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering close-session protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	csp := protocol.(*protocols.CloseSessionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting close-session protocol")
	err = csp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = csp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(csp.ServerIdentity(), "Waiting for close-session protocol to terminate...")
	csp.WaitDone()
	// At this point, the session has been closed

	log.Lvl2(service.ServerIdentity(), "Closed Session!")

	return nil
}

*/

// This method is executed at the server when receiving the root's GetPubKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetPubKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetPubKeyReply)

	log.Lvl2(service.ServerIdentity(), "Received GetPubKeyReply:", reply.ReqID)

	// Simply send reply through channel
	service.getPubKeyRepLock.RLock()
	service.getPubKeyReplies[reply.ReqID] <- reply
	service.getPubKeyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
