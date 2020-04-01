package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

func (s *Service) HandleRetrieveQuery(query *RetrieveQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received RetrieveQuery for ciphertext:", query.CipherID)

	// Create RetrieveRequest with its ID
	reqID := newRetrieveRequestID()
	req := RetrieveRequest{reqID, query}

	// Create channel before sending request to root.
	s.retrieveReplies[reqID] = make(chan *RetrieveReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending RetrieveRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send RetrieveRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.retrieveReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.valid {
		err := errors.New("Received invalid reply: root couldn't perform key-switch")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &RetrieveResponse{reply.ciphertext, reply.valid}, nil
}

func (s *Service) processRetrieveRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received RetrieveRequest.")

	req := (msg.Msg).(*RetrieveRequest)
	reply := RetrieveReply{RetrieveRequestID: req.RetrieveRequestID}

	// Check existence of ciphertext
	ct, ok := s.database[req.CipherID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.CipherID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Build preparation message to broadcast
	prep := RetrieveBroadcast{req.RetrieveRequestID,
		&SwitchingParameters{req.PublicKey, ct}}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	err := utils.Broadcast(s.ServiceProcessor, &s.Roster, prep)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not broadcast preparation message:", err)
		err = s.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, launch the public key-switching protocol to get the switched ciphertext
	log.Lvl2(s.ServerIdentity(), "Switching ciphertext")
	ctSwitch, err := s.switchCiphertext()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not perform key-switching:", err)
		err := s.SendRaw(msg.ServerIdentity, reply) // Field ciphertext stays nil and field valid stay false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(s.ServerIdentity(), "Successfully switched ciphertext")

	// Set fields in the reply
	reply.ciphertext = ctSwitch
	reply.valid = true

	// Send the positive reply to the server
	log.Lvl2(s.ServerIdentity(), "Replying (positively) to server")
	err = s.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (s *Service) processRetrieveBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*RetrieveBroadcast)

	// Send the SwitchingParameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending switching parameters through channel")
	s.switchingParams <- prep.params

	log.Lvl4(s.ServerIdentity(), "Sent switching parameters through channel")

	return
}

func (s *Service) switchCiphertext() (*bfv.Ciphertext, error) {
	log.Lvl2(s.ServerIdentity(), "Performing public key-switching")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating PCKS protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectivePublicKeySwitchingProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate PCKS protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering PCKS protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// Start the protocol
	log.Lvl2(s.ServerIdentity(), "Starting PCKS protocol")
	err = pcks.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start PCKS protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = pcks.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch PCKS protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(pcks.ServerIdentity(), "Waiting for PCKS protocol to terminate...")
	pcks.Wait()

	log.Lvl2(s.ServerIdentity(), "Switched ciphertext!")

	return &pcks.CiphertextOut, nil
}

func (s *Service) processRetrieveReply(msg *network.Envelope) {
	reply := (msg.Msg).(*RetrieveReply)

	log.Lvl1(s.ServerIdentity(), "Received RetrieveReply")

	// Simply send reply through channel
	s.retrieveReplies[reply.RetrieveRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
