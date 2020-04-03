package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

func (smc *Service) HandleSharesToEncQuery(query *SharesToEncQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received SharesToEncQuery for ciphertext:", query.CipherID)

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create SharesToEncRequest with its ID
	reqID := newSharesToEncRequestID()
	req := SharesToEncRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.sharesToEncReplies[reqID] = make(chan *SharesToEncReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending SharesToEncRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send SharesToEncRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.sharesToEncReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform shares-to-enc")
		log.Error(smc.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(smc.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &SharesToEncResponse{reply.Valid}, nil
}

func (smc *Service) processSharesToEncRequest(msg *network.Envelope) {
	req := (msg.Msg).(*SharesToEncRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received SharesToEncRequest.")

	// Start by declaring reply with minimal fields.
	reply := &SharesToEncReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// The check for existence of the share is done in the protocol factory, since it is a problem of every node

	/*
		// Build preparation message to broadcast
		prep := SharesToEncBroadcast{req.ReqID,
			&S2EParameters{req.Query.CipherID}}

		// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
		log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
		err := utils.Broadcast(s.ServiceProcessor, s.Roster, prep)
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not broadcast preparation message:", err)
			err = s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
			if err != nil {
				log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
			}

			return
		}
	*/

	// Then, launch the shares-to-enc protocol to get the re-encrypted ciphertext
	log.Lvl2(smc.ServerIdentity(), "Re-encrypting ciphertext")
	ctReenc, err := smc.reencryptCiphertext(req.SessionID, req.Query.CipherID)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not perform shares-to-enc:", err)
		err := smc.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Register (overwrite) in the local database
	s.database[req.Query.CipherID] = ctReenc

	log.Lvl3(smc.ServerIdentity(), "Successfully re-encrypted ciphertext")

	// Set fields in the reply
	reply.Valid = true

	// Send the positive reply to the server
	log.Lvl2(smc.ServerIdentity(), "Replying (positively) to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

/*
func (s *Service) processSharesToEncBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*SharesToEncBroadcast)

	// Send the shares-to-enc parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending sharesToEnc parameters through channel")
	s.sharesToEncParams <- prep.Params

	log.Lvl4(s.ServerIdentity(), "Sent sharesToEnc parameters through channel")

	return
}
*/

func (smc *Service) reencryptCiphertext(SessionID SessionID, CipherID CipherID) (*bfv.Ciphertext, error) {
	log.Lvl2(smc.ServerIdentity(), "Re-encrypting a ciphertext")

	// Extract session
	s, _ := smc.sessions[SessionID] // If we got to this point, surely the Session must exist

	// Create TreeNodeInstance as root (this method runs on the root)
	tree := s.Roster.GenerateBinaryTree()
	tni := smc.NewTreeNodeInstance(tree, tree.Root, SharesToEncProtocolName)

	// Create configuration for the protocol instance
	config := &S2EConfig{SessionID, CipherID}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating shares-to-enc protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate shares-to-enc protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering shares-to-enc protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	s2e := protocol.(*protocols.SharesToEncryptionProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting shares-to-enc protocol")
	err = s2e.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start shares-to-enc protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = s2e.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch shares-to-enc protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(s2e.ServerIdentity(), "Waiting for shares-to-enc protocol to terminate...")
	ctReenc := <-s2e.ChannelCiphertext

	log.Lvl2(smc.ServerIdentity(), "Shared ciphertext!")

	return ctReenc, nil
}

func (smc *Service) processSharesToEncReply(msg *network.Envelope) {
	reply := (msg.Msg).(*SharesToEncReply)

	log.Lvl1(smc.ServerIdentity(), "Received SharesToEncReply")

	// Extract Session, if existent
	s, ok := smc.sessions[reply.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.sharesToEncReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
