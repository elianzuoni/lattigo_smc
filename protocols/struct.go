package protocols

import (
	"github.com/lca1/lattigo/bfv"
	"github.com/lca1/lattigo/ring"
	"go.dedis.ch/onet/v3"
)

type CollectiveKeyGenerationProtocol struct {
	*onet.TreeNodeInstance

	Params bfv.Parameters

	ChannelParams          chan StructParameters
	ChannelPublicKeyShares chan StructPublicKeyShare
	ChannelPublicKey       chan StructPublicKey
}

type Parameters struct {
	Params bfv.Parameters
}

type PublicKeyShare struct {
	ring.Poly
	//Message string
}

type PublicKey struct {
	ring.Poly
}

type StructParameters struct {
	*onet.TreeNode
	Parameters
}

type StructPublicKeyShare struct {
	*onet.TreeNode
	PublicKeyShare
}

type StructPublicKey struct {
	*onet.TreeNode
	PublicKey
}