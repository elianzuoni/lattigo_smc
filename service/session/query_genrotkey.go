package session

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleGenRotKeyQuery(query *messages.GenRotKeyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received GenRotKeyQuery")

	/*
		// Extract Session, if existent
		s, ok := service.sessions.GetSession(query.SessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Create GenRotKeyRequest with its ID
		reqID := messages.NewGenRotKeyRequestID()
		req := &messages.GenRotKeyRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.genRotKeyRepLock.Lock()
		service.genRotKeyReplies[reqID] = make(chan *messages.GenRotKeyReply)
		service.genRotKeyRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending GenRotKeyRequest to root:", reqID)
		err := service.SendRaw(s.Root, req)
		if err != nil {
			err = errors.New("Couldn't send GenRotKeyRequest to root: " + err.Error())
			log.Error(err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
		service.genRotKeyRepLock.RLock()
		replyChan := service.genRotKeyReplies[reqID]
		service.genRotKeyRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.genRotKeyRepLock.Lock()
		close(replyChan)
		delete(service.genRotKeyReplies, reqID)
		service.genRotKeyRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel")

		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't generate public key")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		} else {
			log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")
		}

		return &messages.GenRotKeyResponse{reply.Valid}, nil

	*/

	// Extract Session, if existent (actually, only check existence)
	_, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Then, launch the genRotKey protocol to generate the RotationKey
	log.Lvl2(service.ServerIdentity(), "Generating Rotation Key")
	err := service.genRotKey(query.SessionID, query.RotIdx, query.K, query.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not generate rotation key:", err)
		return nil, err
	}

	log.Lvl3(service.ServerIdentity(), "Successfully generated rotation key")

	return &messages.GenRotKeyResponse{true}, nil
}

func (service *Service) genRotKey(SessionID messages.SessionID, rotIdx int, K uint64, Seed []byte) error {
	log.Lvl1(service.ServerIdentity(), "Root. Generating EvaluationKey")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Reduce K modulo n/2 (each row is long n/2)
	K &= (1 << (s.Params.LogN - 1)) - 1

	// Only left-rotation is available. If right-rotation is requested, transform it into a left-rotation.
	if rotIdx == bfv.RotationRight {
		rotIdx = bfv.RotationLeft
		K = (1 << (s.Params.LogN - 1)) - K
	}

	// Lock the rotation key (no check for existence: can be overwritten)
	// We must hold the lock until the end, because only at the end is the RotKey generated.
	// We can do so, because no other lock will be is held by this goroutine, or by any other one waiting for
	// this or for which this waits.
	s.rotKeyLock.Lock()
	defer s.rotKeyLock.Unlock()

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.RotationProtocolName)

	// Create configuration for the protocol instance
	config := &messages.GenRotKeyConfig{SessionID, rotIdx, K, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating RKG protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate RKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering RKG protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	rkgp := protocol.(*protocols.RotationKeyProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting RKG protocol")
	err = rkgp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start RKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = rkgp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch RKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(rkgp.ServerIdentity(), "Waiting for RKG protocol to terminate...")
	rkgp.WaitDone()

	// Retrieve rotationKey
	s.rotationKey = &rkgp.RotKey
	log.Lvl1(service.ServerIdentity(), "Generated rotationKey!")

	return nil
}
