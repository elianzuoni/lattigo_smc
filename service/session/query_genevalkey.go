package session

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleGenEvalKeyQuery(query *messages.GenEvalKeyQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received GenEvalKeyQuery")

	// Extract Session, if existent (actually, only check existence)
	_, ok := service.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Then, launch the genEvalKey protocol to generate the EvaluationKey
	log.Lvl2(service.ServerIdentity(), "Generating Evaluation Key")
	err := service.genEvalKey(query.SessionID, query.Seed)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not generate evaluation key:", err)
		return nil, err
	}

	log.Lvl3(service.ServerIdentity(), "Successfully generated evaluation key")

	return &messages.GenEvalKeyResponse{true}, nil
}

func (service *Service) genEvalKey(SessionID messages.SessionID, Seed []byte) error {
	log.Lvl2(service.ServerIdentity(), "Generating EvaluationKey")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Check that evalKey is not generated
	// We must hold the lock until the end, because only at the end the evalKey is generated
	// We can do so, because no other lock is held by this goroutine, or any other which waits for this
	// or for which this waits.
	s.evalKeyLock.Lock()
	defer s.evalKeyLock.Unlock()
	if s.evalKey != nil {
		err := errors.New("Evaluation key is already set")
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
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.RelinearizationKeyProtocolName)

	// Create configuration for the protocol instance
	config := &messages.GenEvalKeyConfig{SessionID, Seed}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	conf := onet.GenericConfig{data}
	log.Lvl3(service.ServerIdentity(), "Instantiating EKG protocol")
	protocol, err := service.NewProtocol(tni, &conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate EKG protocol", err)
		return err
	}
	tni.SetConfig(&conf)

	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering EKG protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ekgp := protocol.(*protocols.RelinearizationKeyProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting EKG protocol")
	err = ekgp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start EKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ekgp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch EKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ekgp.ServerIdentity(), "Waiting for EKG protocol to terminate...")
	ekgp.WaitDone()

	// Retrieve EvaluationKey
	s.evalKey = ekgp.EvaluationKey
	log.Lvl1(service.ServerIdentity(), "Generated EvaluationKey!")

	return nil
}
