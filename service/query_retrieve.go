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
	tree := s.Roster.GenerateBinaryTree()

	log.Lvl1("Received RetrieveQuery")

	// Delegate everything to the root
	log.Lvl2(s.ServerIdentity(), "Forwarding request to the root")
	req := (*RetrieveRequest)(query)
	s.SendRaw(tree.Root.ServerIdentity, req)

	// Receive swtiched ciphertext from channel
	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root. Waiting to receive switched ciphertext...")
	cipher := <-s.switchedCiphertext // TODO: timeout if root cannot send reply
	if cipher == nil {
		err := errors.New("Received nil ciphertext: root couldn't perform key-switch")
		log.Error(s.ServerIdentity(), err)
		return &RetrieveResponse{nilCipherID, nil, false}, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid new ciphertext from channel")
	// TODO: close channel?

	return &RetrieveResponse{req.ID, cipher, true}, nil
}

func (s *Service) processRetrieveRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received RetrieveRequest.")

	req := (msg.Msg).(*RetrieveRequest)

	// Check existence of ciphertext
	ct, ok := s.database[req.ID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.ID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, &RetrieveReply{nilCipherID, nil, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	utils.Broadcast(s.ServiceProcessor, &s.Roster, &RetrieveBroadcast{req.PublicKey, ct})

	// Then, launch the public key-switching protocol to get the switched ciphertext
	log.Lvl2(s.ServerIdentity(), "Switching ciphertext")
	cipher, err := s.switchCiphertext()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not perform key-switching:", err)
		err := s.SendRaw(msg.ServerIdentity, &RetrieveReply{nilCipherID, nil, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	log.Lvl3(s.ServerIdentity(), "Successfully switched ciphertext")

	// Send the positive reply to the server
	log.Lvl2(s.ServerIdentity(), "Replying (positively) to server")
	err = s.SendRaw(msg.ServerIdentity, &RetrieveReply{req.ID, cipher, true})
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
	s.switchingParameters <- (*SwitchingParameters)(prep)

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
	log.Lvl3(s.ServerIdentity(), "Registering PCKS protocol")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	//<-time.After(1 * time.Second) // TODO: maybe not needed with channel

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
	rep := (msg.Msg).(*RetrieveReply)

	log.Lvl1(s.ServerIdentity(), "Received RetrieveReply")

	// Check validity
	if !rep.valid {
		log.Error(s.ServerIdentity(), "The received RetrieveReply is invalid")
		s.switchedCiphertext <- nil
		return
	}

	log.Lvl3(s.ServerIdentity(), "The received RetrieveReply is valid. Sending through channel")
	s.switchedCiphertext <- rep.Ciphertext
	log.Lvl4(s.ServerIdentity(), "Sent switched ciphertext through channel")

	return
}
