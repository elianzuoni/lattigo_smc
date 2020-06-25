// This file contains the interfaces that abstract the structures in the Services
// and extrapolate their minimal behaviour needed for the protocols.

package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"lattigo-smc/service/messages"
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
