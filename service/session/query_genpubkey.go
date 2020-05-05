package session

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleGenPubKeyQuery(query *messages.GenPubKeyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received GenPubKeyQuery")

	/*
		// Extract Session, if existent
		s, ok := service.sessions.GetSession(query.SessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Create GenPubKeyRequest with its ID
		reqID := messages.NewGenPubKeyRequestID()
		req := &messages.GenPubKeyRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.genPubKeyRepLock.Lock()
		service.genPubKeyReplies[reqID] = make(chan *messages.GenPubKeyReply)
		service.genPubKeyRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending GenPubKeyRequest to root:", reqID)
		err := service.SendRaw(s.Root, req)
		if err != nil {
			err = errors.New("Couldn't send GenPubKeyRequest to root: " + err.Error())
			log.Error(err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
		service.genPubKeyRepLock.RLock()
		replyChan := service.genPubKeyReplies[reqID]
		service.genPubKeyRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.genPubKeyRepLock.Lock()
		close(replyChan)
		delete(service.genPubKeyReplies, reqID)
		service.genPubKeyRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel")

		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't generate public key")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		} else {
			log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")
		}

		return &messages.GenPubKeyResponse{reply.MasterPublicKey, reply.Valid}, nil

	*/

	// Extract Session, if existent (actually, only check existence)
	s, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Then, launch the genPublicKey protocol to generate the publicKey
	log.Lvl2(service.ServerIdentity(), "Generating Public Key")
	err := service.genPublicKey(query.SessionID, query.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not generate public key:", err)
		return nil, err
	}

	log.Lvl3(service.ServerIdentity(), "Successfully generated public key")

	// Get the public key
	pk, ok := s.GetPublicKey()
	// Hope that it exists
	if !ok {
		panic("What the hell? Generated public key, but GetPublicKey did not find it!")
	}

	return &messages.GenPubKeyResponse{pk, true}, nil
}

func (service *Service) genPublicKey(SessionID messages.SessionID, Seed []byte) error {
	log.Lvl1(service.ServerIdentity(), "Root. Generating PublicKey")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Check that PubKey is not generated
	// We must hold the lock until the end, because only at the end the PubKey is generated
	// We can do so, because no other lock is held by this goroutine, or any other which waits for this
	// or for which this waits.
	s.pubKeyLock.Lock()
	defer s.pubKeyLock.Unlock()
	if s.publicKey != nil {
		err := errors.New("publicKey is already set")
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
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveKeyGenerationProtocolName)

	// Create configuration for the protocol instance
	config := &messages.GenPubKeyConfig{SessionID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating CKG protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate CKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering CKG protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting CKG protocol")
	err = ckgp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start CKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ckgp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch CKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ckgp.ServerIdentity(), "Waiting for CKG protocol to terminate...")
	ckgp.WaitDone()

	// Retrieve PublicKey
	s.publicKey = ckgp.Pk
	log.Lvl1(service.ServerIdentity(), "Generated PublicKey!")

	return nil
}
