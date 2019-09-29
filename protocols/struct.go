package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
)



type KeyRing struct {
	//Ideally use maybe this in the future to have a single structure.. but maybe it will get too big ~ check later
	//everything needed for the keys.
	//*dbfv.CKG
	//*dbfv.EkgProtocol
	//*dbfv.PCKS

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
	ChannelCKSShare chan StructCKSShare
}

type StructCKSShare struct{
	*onet.TreeNode
	ring.Poly
}
type SwitchingParameters struct{
	Params bfv.Parameters
	//also need skIn, skOut
	SkInput ring.Poly
	SkOutput ring.Poly
	cipher bfv.Ciphertext
}

type StructSwitchParameters struct{
	*onet.TreeNode
	SwitchingParameters
}

type StructCiphertext struct{
	*onet.TreeNode
	bfv.Ciphertext
}

//type Parameters struct {
//	Params bfv.Parameters
//}
//
//type PublicKey struct {
//	ring.Poly
//}
//type Parameters struct{
//	Params bfv.Parameters
//}
type CollectiveKeyShare struct {
	ring.Poly
}


type StructParameters struct {
	*onet.TreeNode
	Params bfv.Parameters
}



type StructPublicKeyShare struct {
	*onet.TreeNode
	CollectiveKeyShare
}

type StructPublicKey struct {
	*onet.TreeNode
	ring.Poly
}