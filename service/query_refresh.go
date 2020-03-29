package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

func (s *Service) HandleRefreshQuery(query *RefreshQuery) (network.Message, error) {
	tree := s.Roster.GenerateBinaryTree()

	log.Lvl1("Received RefreshQuery")

	// Delegate everything to the root
	log.Lvl2(s.ServerIdentity(), "Forwarding request to the root")
	req := (*RefreshRequest)(query)
	s.SendRaw(tree.Root.ServerIdentity, req)

	// Receive swtiched ciphertext from channel
	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root. Waiting to receive refreshed ciphertext...")
	cipher := <-s.refreshedCiphertext // TODO: timeout if root cannot send reply
	if cipher == nil {
		err := errors.New("Received nil ciphertext: root couldn't perform refresh")
		log.Error(s.ServerIdentity(), err)
		return &RefreshResponse{nilCipherID, nil, false}, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid new ciphertext from channel")
	// TODO: close channel?

	return &RefreshResponse{req.ID, cipher, true}, nil
}

func (s *Service) processRefreshRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received RefreshRequest.")

	req := (msg.Msg).(*RetrieveRequest)

	// Check existence of ciphertext
	ct, ok := s.database[req.ID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.ID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, &RefreshReply{nilCipherID, nil, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	utils.Broadcast(s.ServiceProcessor, &s.Roster, &RefreshBroadcast{ct})

	// Then, launch the refresh protocol to get the refreshed ciphertext
	log.Lvl2(s.ServerIdentity(), "Refreshing ciphertext")
	cipher, err := s.refreshCiphertext()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not perform refresh:", err)
		err := s.SendRaw(msg.ServerIdentity, &RefreshReply{nilCipherID, nil, false})
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// Register (overwrite) in the local database
	s.database[req.ID] = cipher

	log.Lvl3(s.ServerIdentity(), "Successfully refreshed ciphertext")

	// Send the positive reply to the server
	log.Lvl2(s.ServerIdentity(), "Replying (positively) to server")
	err = s.SendRaw(msg.ServerIdentity, &RefreshReply{req.ID, cipher, true})
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (s *Service) processRefreshBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*RefreshBroadcast)

	// Send the refresh parameters thorugh the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending refresh parameters through channel")
	s.refreshParams <- prep.ct

	log.Lvl4(s.ServerIdentity(), "Sent refresh parameters through channel")

	return
}

func (s *Service) refreshCiphertext() (*bfv.Ciphertext, error) {
	log.Lvl2(s.ServerIdentity(), "Performing refresh")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating refresh protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveRefreshName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate refresh protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering refresh protocol")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	refresh := protocol.(*protocols.RefreshProtocol)

	//<-time.After(1 * time.Second) // TODO: maybe not needed with channel

	// Start the protocol
	log.Lvl2(s.ServerIdentity(), "Starting refresh protocol")
	err = refresh.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start refresh protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = refresh.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch refresh protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(refresh.ServerIdentity(), "Waiting for refresh protocol to terminate...")
	refresh.Wait()

	log.Lvl2(s.ServerIdentity(), "Refreshed ciphertext!")

	return &refresh.Ciphertext, nil
}

func (s *Service) processRefreshReply(msg *network.Envelope) {
	rep := (msg.Msg).(*RefreshReply)

	log.Lvl1(s.ServerIdentity(), "Received RefreshReply")

	// Check validity
	if !rep.valid {
		log.Error(s.ServerIdentity(), "The received RefreshReply is invalid")
		s.refreshedCiphertext <- nil
		return
	}

	log.Lvl3(s.ServerIdentity(), "The received RefreshReply is valid. Sending through channel")
	s.refreshedCiphertext <- rep.ct
	log.Lvl4(s.ServerIdentity(), "Sent refreshed ciphertext through channel")

	return
}
