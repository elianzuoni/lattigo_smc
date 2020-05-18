// The goal of the CreateSession query is to create a new Session

package session

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/protocols"
)

func (service *Service) HandleCreateSessionQuery(query *messages.CreateSessionQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received CreateSessionQuery")

	// Decide the SessionID (it has to be uniquely identifying across the system, so we generate it here)
	sessionID := messages.NewSessionID()

	// Launch the CreateSession protocol, to create the Session at all nodes
	err := service.createSession(sessionID, query.Roster, query.Params)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not create session:", err)
		return nil, err
	}

	return &messages.CreateSessionResponse{sessionID, true}, nil
}

// Creates a session at all nodes, launching the CreateSession protocol (establishes itself as the root for the session).
func (service *Service) createSession(SessionID messages.SessionID, roster *onet.Roster, params *bfv.Parameters) error {
	log.Lvl2(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Creating a session")

	// Create TreeNodeInstance as root
	tree := roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, CreateSessionProtocolName)

	// Create configuration for the protocol instance
	config := &messages.CreateSessionConfig{SessionID, roster, params}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Instantiating create-session protocol")
	conf := onet.GenericConfig{data}
	protocol, err := service.NewProtocol(tni, &conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate create-session protocol", err)
		return err
	}
	tni.SetConfig(&conf)

	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Registering create-session protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	csp := protocol.(*protocols.CreateSessionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Starting create-session protocol")
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
	log.Lvl2(csp.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Waiting for create-session protocol to terminate...")
	csp.WaitDone()
	// At this point, the session has been created

	log.Lvl2(service.ServerIdentity(), "(SessionID =", SessionID, ")\n", "Created Session!")

	return nil
}
