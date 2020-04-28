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

func (service *Service) HandleSharesToEncQuery(query *messages.SharesToEncQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SharesToEncQuery for shares:", query.SharesID)

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create SharesToEncRequest with its ID
	reqID := messages.NewSharesToEncRequestID()
	req := &messages.SharesToEncRequest{query.SessionID, reqID, query}

	// Create channel before sending request to root.
	s.SharesToEncRepLock.Lock()
	s.SharesToEncReplies[reqID] = make(chan *messages.SharesToEncReply)
	s.SharesToEncRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending SharesToEncRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := service.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send SharesToEncRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	s.SharesToEncRepLock.RLock()
	replyChan := s.SharesToEncReplies[reqID]
	s.SharesToEncRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	s.SharesToEncRepLock.Lock()
	close(replyChan)
	delete(s.SharesToEncReplies, reqID)
	s.SharesToEncRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform shares-to-enc")
		log.Error(service.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")

	return &messages.SharesToEncResponse{reply.NewCipherID, reply.Valid}, nil
}

func (service *Service) processSharesToEncRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.SharesToEncRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received SharesToEncRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.SharesToEncReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Then, launch the shares-to-enc protocol to get the re-encrypted ciphertext
	log.Lvl2(service.ServerIdentity(), "Re-encrypting ciphertext")
	ctReenc, err := service.reencryptCiphertext(req.SessionID, req.Query.SharesID, req.Query.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not perform shares-to-enc:", err)
		err := service.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Register in the local database
	newCipherID := messages.NewCipherID(service.ServerIdentity())
	s.StoreCiphertext(newCipherID, ctReenc)

	log.Lvl3(service.ServerIdentity(), "Successfully re-encrypted ciphertext")

	// Set fields in the reply
	reply.Valid = true
	reply.NewCipherID = newCipherID

	// Send the positive reply to the server
	log.Lvl2(service.ServerIdentity(), "Replying (positively) to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (service *Service) reencryptCiphertext(SessionID messages.SessionID, SharesID messages.SharesID, Seed []byte) (*bfv.Ciphertext, error) {
	log.Lvl2(service.ServerIdentity(), "Re-encrypting a ciphertext")

	// Extract session
	s, ok := service.GetSessionService().GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, SharesToEncProtocolName)

	// Create configuration for the protocol instance
	config := &messages.S2EConfig{SessionID, SharesID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating shares-to-enc protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate shares-to-enc protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering shares-to-enc protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	s2e := protocol.(*protocols.SharesToEncryptionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting shares-to-enc protocol")
	err = s2e.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start shares-to-enc protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = s2e.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch shares-to-enc protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(s2e.ServerIdentity(), "Waiting for shares-to-enc protocol to terminate...")
	s2e.WaitDone()
	ctReenc := s2e.OutputCiphertext

	log.Lvl2(service.ServerIdentity(), "Shared ciphertext!")

	return ctReenc, nil
}

func (service *Service) processSharesToEncReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.SharesToEncReply)

	log.Lvl1(service.ServerIdentity(), "Received SharesToEncReply")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(reply.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		return
	}

	// Simply send reply through channel
	s.SharesToEncRepLock.RLock()
	s.SharesToEncReplies[reply.ReqID] <- reply
	s.SharesToEncRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
