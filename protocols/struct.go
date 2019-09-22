package protocols

import (
	"github.com/lca1/lattigo/bfv"
	"github.com/lca1/lattigo/dbfv"
	"github.com/lca1/lattigo/ring"
	"go.dedis.ch/onet/v3"
)



type KeyRing struct {
	//everything needed for the keys.
	*dbfv.CKG
	*dbfv.EkgProtocol
	*dbfv.PCKS

	sk *bfv.SecretKey
	rlkEphemSk *ring.Poly
	input []uint64
}



type CollectiveKeyGenerationProtocol struct {
	*onet.TreeNodeInstance

	Params bfv.Parameters

	ChannelParams          chan StructParameters
	ChannelPublicKeyShares chan StructPublicKeyShare
	ChannelPublicKey       chan StructPublicKey
}


type CollectiveKeySwitchingProtocol struct{
	*onet.TreeNodeInstance

	Params SwitchingParameters

	ChannelParams chan StructSwitchParameters
	ChannelCiphertext chan StructCiphertext
	ChannelPublicKey chan StructPublicKey
}

type SwitchingParameters struct{
	Params Parameters
	//also need skIn, skOut
	Skinput ring.Poly
	SkOutput ring.Poly
	cipher bfv.Ciphertext
}

type StructSwitchParameters struct{
	*onet.TreeNodeInstance
	SwitchingParameters
}

type StructCiphertext struct{
	*onet.TreeNodeInstance
	bfv.Ciphertext
}

type Parameters struct {
	Params bfv.Parameters
}

type PublicKeyShare struct {
	ring.Poly
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