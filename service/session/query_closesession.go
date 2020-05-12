// The goal of the CloseSession query is to close an existing Session

package session

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/protocols"
)

func (service *Service) HandleCloseSessionQuery(query *messages.CloseSessionQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received CloseSessionQuery")

	// Launch the CloseSession protocol, to delete the Session at all nodes
	err := service.closeSession(query.SessionID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not close session:", err)

		return nil, err
	}

	return &messages.CloseSessionResponse{true}, nil
}

func (service *Service) closeSession(SessionID messages.SessionID) error {
	log.Lvl2(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Closing a session")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", err)
		return err
	}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, CloseSessionProtocolName)

	// Create configuration for the protocol instance
	config := &messages.CloseSessionConfig{SessionID}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Instantiating close-session protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Could not instantiate create-session protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Registering close-session protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Could not register protocol instance:", err)
		return err
	}

	csp := protocol.(*protocols.CloseSessionProtocol)

	// Start the protocol
	log.Lvl3(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Starting close-session protocol")
	err = csp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = csp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(csp.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Waiting for close-session protocol to terminate...")
	csp.WaitDone()
	// At this point, the session has been closed

	log.Lvl2(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Closed Session!")

	return nil
}
