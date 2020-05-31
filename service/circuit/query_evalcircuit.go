package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/protocols"
)

func (service *Service) HandleEvalCircuitQuery(query *messages.EvalCircuitQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received EvalCircuitQuery")

	// Extract Circuit, if existent
	c, ok := service.GetCircuit(query.CircuitID)
	if !ok {
		err := errors.New("Requested circuit does not exist")
		log.Error(service.ServerIdentity(), "(CircuitID =", query.CircuitID, ")\n", err)
		return nil, err
	}

	// Launch evaluation and get result
	resID := c.OperationTree.Evaluate()
	if resID == messages.NilCipherID {
		err := errors.New("Evaluation returned invalid result")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	log.Lvl3(service.ServerIdentity(), "Got the result!")

	// Launch the CloseCircuit protocol, to delete the Circuit at all nodes
	err := service.closeCircuit(query.CircuitID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not close circuit:", err)

		return nil, err
	}

	return &messages.EvalCircuitResponse{resID, true}, nil
}

func (service *Service) closeCircuit(circuitID messages.CircuitID) error {
	log.Lvl2(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Closing a circuit")

	// Extract Circuit, if existent
	c, ok := service.GetCircuit(circuitID)
	if !ok {
		err := errors.New("Requested circuit does not exist")
		log.Error(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", err)
		return err
	}

	// Create configuration for the protocol instance
	config := &messages.CloseCircuitConfig{circuitID}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Could not marshal protocol configuration:", err)
		return err
	}
	conf := onet.GenericConfig{data}

	// Create TreeNodeInstance as root
	tree := c.session.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, CloseCircuitProtocolName)
	err = tni.SetConfig(&conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Could not set config:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Instantiating protocol")
	protocol, err := service.NewProtocol(tni, &conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol", err)
		return err
	}

	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Registering protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Could not register protocol instance:", err)
		return err
	}

	ccp := protocol.(*protocols.CloseCircuitProtocol)

	// Start the protocol
	log.Lvl3(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Starting close-circuit protocol")
	err = ccp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start close-circuit protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ccp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch close-circuit protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ccp.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Waiting for close-circuit protocol to terminate...")
	ccp.WaitDone()
	// At this point, the circuit has been closed

	log.Lvl2(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", "Closed Circuit!")

	return nil
}
