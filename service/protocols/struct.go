package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"sync"
)

// This interface is implemented by the SessionStore struct. It extrapolates the behaviour required to run the
// CreateSession and CloseSession protocols.
type AbstractSessionStore interface {
	NewSession(id messages.SessionID, roster *onet.Roster, root *network.ServerIdentity, params *bfv.Parameters)
	DeleteSession(id messages.SessionID)
}

type CreateSessionProtocol struct {
	*onet.TreeNodeInstance

	store     AbstractSessionStore
	SessionID messages.SessionID
	roster    *onet.Roster
	root      *network.ServerIdentity
	params    *bfv.Parameters

	// Channels to receive from other nodes.
	channelStart chan StructStart
	channelDone  chan []StructDone // A channel of slices allows to receive all shares at once.

	// Used ot wait for termination.
	done sync.Mutex
}

type CloseSessionProtocol struct {
	*onet.TreeNodeInstance

	store     AbstractSessionStore
	SessionID messages.SessionID

	// Channels to receive from other nodes.
	channelStart chan StructStart
	channelDone  chan []StructDone // A channel of slices allows to receive all shares at once.

	// Used ot wait for termination.
	done sync.Mutex
}

// The Start message is sent to wake up the children.
type Start struct{}

// StructStart is a handler for onet.
// Wraps the Start message so that it can
// be passed via onet with the paradigm described in cothority_template
type StructStart struct {
	*onet.TreeNode
	Start
}

// The Done message is sent to signal completion.
type Done struct{}

// StructDone is a handler for onet.
// Wraps the Done message so that it can
// be passed via onet with the paradigm described in cothority_template
type StructDone struct {
	*onet.TreeNode
	Done
}
