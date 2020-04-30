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

// Legacy query
func (service *Service) HandleRetrieveQuery(query *messages.RetrieveQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received RetrieveQuery for ciphertext:", query.CipherID)

	/*
		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(query.SessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Create RetrieveRequest with its ID
		reqID := messages.NewRetrieveRequestID()
		req := &messages.RetrieveRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.retrieveRepLock.Lock()
		service.retrieveReplies[reqID] = make(chan *messages.RetrieveReply)
		service.retrieveRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending RetrieveRequest to root:", reqID)
		tree := s.Roster.GenerateBinaryTree()
		err := service.SendRaw(tree.Root.ServerIdentity, req)
		if err != nil {
			err = errors.New("Couldn't send RetrieveRequest to root: " + err.Error())
			log.Error(err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
		service.retrieveRepLock.RLock()
		replyChan := service.retrieveReplies[reqID]
		service.retrieveRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.retrieveRepLock.Lock()
		close(replyChan)
		delete(service.retrieveReplies, reqID)
		service.retrieveRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel")

		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't perform key-switch")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		}
		log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")

		return &messages.RetrieveResponse{reply.Ciphertext, reply.Valid}, nil

	*/

	switchedCipher, err := service.switchCipher(query.SessionID, query.PublicKey, query.CipherID)
	return &messages.RetrieveResponse{switchedCipher, err == nil}, err
}

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
	config := &messages.PublicSwitchConfig{sessionID, pk, ct}
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

// To be modified

func (service *Service) processRetrieveRequest(msg *network.Envelope) {
	/*
		req := (msg.Msg).(*messages.RetrieveRequest)

		log.Lvl1(service.ServerIdentity(), "Root. Received RetrieveRequest.")

		// Start by declaring reply with minimal fields.
		reply := &messages.RetrieveReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(req.SessionID)
		if !ok {
			log.Error(service.ServerIdentity(), "Requested session does not exist")
			// Send negative response
			err := service.SendRaw(msg.ServerIdentity, &reply)
			if err != nil {
				log.Error("Could not send reply:", err)
			}
			return
		}

		// Check existence of ciphertext
		ct, ok := s.GetCiphertext(req.Query.CipherID)
		if !ok {
			log.Error(service.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
			err := service.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
			if err != nil {
				log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
			}

			return
		}

		// Then, launch the public key-switching protocol to get the switched ciphertext
		log.Lvl2(service.ServerIdentity(), "Switching ciphertext")
		ctSwitch, err := service.switchCiphertext(req.SessionID, req.Query.PublicKey, ct)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not perform key-switching:", err)
			err := service.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
			if err != nil {
				log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
			}
			return
		}

		log.Lvl3(service.ServerIdentity(), "Successfully switched ciphertext")

		// Set fields in the reply
		reply.Ciphertext = ctSwitch
		reply.Valid = true

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

func (service *Service) processRetrieveReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RetrieveReply)

	log.Lvl1(service.ServerIdentity(), "Received RetrieveReply")

	// Simply send reply through channel
	service.retrieveRepLock.RLock()
	service.retrieveReplies[reply.ReqID] <- reply
	service.retrieveRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
