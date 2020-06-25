// This file contains all the structure that are used by more than one protocol

package protocols

import (
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
)

//StructStart onet handler
type StructStart struct {
	*onet.TreeNode
	Start
}

//Start This message is used to wake up the children
type Start struct{}

//CRP Wrapper around crp
type CRP struct {
	A []*ring.Poly
}
