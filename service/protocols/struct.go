package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"lattigo-smc/service/messages"
	"sync"
)

// This interface is implemented by the SessionStore struct. It extrapolates the behaviour required to run the
// CreateSession and CloseSession protocols.
type AbstractSessionStore interface {
	NewSession(id messages.SessionID, roster *onet.Roster, params *bfv.Parameters)
	DeleteSession(id messages.SessionID)
}

// This interface is implemented by the CircuitStore struct. It extrapolates the behaviour required to run the
// CreateCircuit and CloseCircuit protocols.
type AbstractCircuitStore interface {
	NewCircuit(circuitID messages.CircuitID, sessionID messages.SessionID, desc string)
	DeleteCircuit(id messages.CircuitID)
}

type CreateSessionProtocol struct {
	*onet.TreeNodeInstance

	store     AbstractSessionStore
	SessionID messages.SessionID
	roster    *onet.Roster
	params    *bfv.Parameters

	// Channels to receive from other nodes.
	channelStart chan StructServStart
	channelDone  chan []StructServDone // A channel of slices allows to receive all shares at once.

	// Used ot wait for termination.
	done sync.Mutex
}

type CloseSessionProtocol struct {
	*onet.TreeNodeInstance

	store     AbstractSessionStore
	SessionID messages.SessionID

	// Channels to receive from other nodes.
	channelStart chan StructServStart
	channelDone  chan []StructServDone // A channel of slices allows to receive all shares at once.

	// Used ot wait for termination.
	done sync.Mutex
}

type CreateCircuitProtocol struct {
	*onet.TreeNodeInstance

	store     AbstractCircuitStore
	CircuitID messages.CircuitID
	SessionID messages.SessionID
	desc      string

	// Channels to receive from other nodes.
	channelStart chan StructServStart
	channelDone  chan []StructServDone // A channel of slices allows to receive all shares at once.

	// Used ot wait for termination.
	done sync.Mutex
}

type CloseCircuitProtocol struct {
	*onet.TreeNodeInstance

	store     AbstractCircuitStore
	CircuitID messages.CircuitID

	// Channels to receive from other nodes.
	channelStart chan StructServStart
	channelDone  chan []StructServDone // A channel of slices allows to receive all shares at once.

	// Used ot wait for termination.
	done sync.Mutex
}

// The ServStart message is sent to wake up the children.
type ServStart struct{}

// StructStart is a handler for onet.
// Wraps the Start message so that it can
// be passed via onet with the paradigm described in cothority_template
type StructServStart struct {
	*onet.TreeNode
	ServStart
}

// The ServDone message is sent to signal completion.
type ServDone struct{}

// StructServDone is a handler for onet.
// Wraps the Done message so that it can
// be passed via onet with the paradigm described in cothority_template
type StructServDone struct {
	*onet.TreeNode
	ServDone
}
