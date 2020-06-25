// This package contains the messages used by more than one protocol

package protocols

import (
	"go.dedis.ch/onet/v3"
)

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
