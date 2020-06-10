package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/circuit/tree"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/protocols"
)

// Handler for reception of CircuitQuery from client.
func (service *Service) HandleCreateCircuitQuery(query *messages.CreateCircuitQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received CreateCircuitQuery")

	// Decide the CircuitID (it has to be uniquely identifying across the system, so we generate it here)
	circuitID := messages.NewCircuitID()

	// Parse circuit description
	log.Lvl3(service.ServerIdentity(), "Going to parse circuit description")
	t := tree.NewBinaryTree(service.treeSupplier(circuitID), service.treeAdder(query.SessionID),
		service.treeMultiplier(query.SessionID), service.treeRotator(query.SessionID))
	err := t.ParseFromRPN(query.Desc)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not parse circuit description:", err)
		return nil, err
	}

	// Launch the CreateCircuit protocol, to create the Circuit at all nodes
	err = service.createCircuit(query.SessionID, circuitID, query.Desc)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not create circuit:", err)
		return nil, err
	}

	// As it is now, the OperationTree is only needed at the "root"

	// Extract Circuit, if existent
	c, ok := service.GetCircuit(circuitID)
	if !ok {
		err := errors.New("Newly-created circuit does not exist!")
		log.Fatal(service.ServerIdentity(), "(CircuitID =", circuitID, ")\n", err)
		return nil, err
	}

	// Set the OperationTree in local circuit
	c.OperationTree = t

	return &messages.CreateCircuitResponse{circuitID, true}, nil
}

// Creates a circuit at all nodes, launching the CreateCircuit protocol (establishes itself as the root for the session).
func (service *Service) createCircuit(sessionID messages.SessionID, circuitID messages.CircuitID,
	desc string) error {
	log.Lvl2(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Creating a circuit")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", err)
		return err
	}

	// Create configuration for the protocol instance
	config := &messages.CreateCircuitConfig{sessionID, circuitID, desc}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Could not marshal protocol configuration:", err)
		return err
	}
	conf := onet.GenericConfig{data}

	// Create TreeNodeInstance as root
	t := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if t == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", err)
		return err
	}
	tni := service.NewTreeNodeInstance(t, t.Root, CreateCircuitProtocolName)
	err = tni.SetConfig(&conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Could not set config:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Instantiating protocol")
	protocol, err := service.NewProtocol(tni, &conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol", err)
		return err
	}

	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Registering protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ccp := protocol.(*protocols.CreateCircuitProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Starting create-circuit protocol")
	err = ccp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start create-circuit protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ccp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch create-circuit protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ccp.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Waiting for create-circuit protocol to terminate...")
	ccp.WaitDone()
	// At this point, the circuit has been created

	log.Lvl2(service.ServerIdentity(), "(SessionID =", sessionID, ", CircuitID =", circuitID, ")\n", "Created Circuit!")

	return nil
}

// Adapts the DelegateSumCiphers method to the signature needed by the OperationTree constructor
func (service *Service) treeAdder(sessionID messages.SessionID) tree.BinaryOperation {
	return func(cipherID1 messages.CipherID, cipherID2 messages.CipherID) (messages.CipherID, error) {
		return service.DelegateSumCiphers(sessionID, cipherID1, cipherID2)
	}
}

// Adapts the DelegateMultiplyCiphers method to the signature needed by the OperationTree constructor
func (service *Service) treeMultiplier(sessionID messages.SessionID) tree.BinaryOperation {
	return func(cipherID1 messages.CipherID, cipherID2 messages.CipherID) (messages.CipherID, error) {
		return service.DelegateMultiplyCiphers(sessionID, cipherID1, cipherID2, true)
	}
}

// Adapts the DelegateRotateCipher method to the signature needed by the OperationTree constructor
func (service *Service) treeRotator(sessionID messages.SessionID) tree.RotOperation {
	return func(cipherID messages.CipherID, rotIdx int, k uint64) (messages.CipherID, error) {
		return service.DelegateRotateCipher(sessionID, cipherID, rotIdx, k)
	}
}

// Adapts the GetCipherID method to the signature needed by the OperationTree constructor
func (service *Service) treeSupplier(circuitID messages.CircuitID) tree.Supplier {
	return func(fullName string) (messages.CipherID, error) {
		log.Lvl2(service.ServerIdentity(), "Resolving name:", fullName)

		// Extract Circuit, if existent
		c, ok := service.GetCircuit(circuitID)
		if !ok {
			err := errors.New("Requested circuit does not exist")
			log.Error(service.ServerIdentity(), err)
			return messages.NilCipherID, err
		}

		id, ok := c.GetCipherID(fullName)
		if !ok {
			err := errors.New("Requested name could not be resolved")
			log.Error(service.ServerIdentity(), err)
			return messages.NilCipherID, err
		}

		return id, nil
	}
}
