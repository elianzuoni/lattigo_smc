package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
)

//type KeyRing struct {
//	//Ideally use maybe this in the future to have a single structure.. but maybe it will get too big ~ check later
//	//everything needed for the keys.
//	//*dbfv.CKG
//	//*dbfv.EkgProtocol
//	//*dbfv.PCKS
//
//	sk         *bfv.SecretKey
//	rlkEphemSk *ring.Poly
//	input      []uint64
//}

type CollectiveKeyGenerationProtocol struct {
	*onet.TreeNodeInstance

	//Parameters of the protocol
	Params bfv.Parameters


	//Channel to send the public key shares or the key at the end.
	ChannelPublicKeyShares chan StructPublicKeyShare
	ChannelPublicKey            chan StructPublicKey
	//Channel to get the wake up
	ChannelStart chan StructStart

}

type CollectiveKeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	Params SwitchingParameters


	ChannelParams     chan StructSwitchParameters
	ChannelCiphertext chan StructCiphertext
	ChannelCKSShare   chan StructCKSShare

	//Channel to wake up
	ChannelStart chan StructStart

}

type CollectivePublicKeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	Params bfv.Parameters
	bfv.PublicKey
	//TODO check if needed - maybe its always the same private key
	Sk SK
	bfv.Ciphertext

	//public parameters
	//ChannelParams chan StructParameters
	//ChannelPublicKey  chan StructPublicKey
	//ChannelSk         chan StructSk
	//

	ChannelCiphertext chan StructCiphertext
	ChannelPCKS       chan StructPCKS

	ChannelStart chan StructStart
}

type RelinearizationKeyProtocol struct {
	*onet.TreeNodeInstance
	Params bfv.Parameters
	//Todo have better variable names once its coded.
	Crp CRP
	//w ring.Poly
	Sk SK
	//Channels to send the different parts of the key
	ChannelRoundOne chan StructRelinKeyRoundOne
	ChannelRoundTwo chan StructRelinKeyRoundTwo
	ChannelRoundThree chan StructRelinKeyRoundThree
	//These are used for testing.
	//In real protocol use Node() from onet to propagate params
	ChannelCrp chan StructCrp
	//ChannelW chan StructPublicKey
	ChannelSk chan StructSk
	ChannelParams chan StructParameters
	ChannelEvalKey chan StructEvalKey

}

type StructEvalKey struct{
	*onet.TreeNode
	bfv.EvaluationKey
}

//channels to propagate parameters for RelinKeyProto
type StructCrp struct{
	*onet.TreeNode
	CRP
}


type StructRelinKeyRoundOne struct{
	*onet.TreeNode
	dbfv.RKGShareRoundOne
}
type StructRelinKeyRoundTwo struct{
	*onet.TreeNode
	dbfv.RKGShareRoundTwo
}
type StructRelinKeyRoundThree struct{
	*onet.TreeNode
	dbfv.RKGShareRoundThree
}
type StructPCKS struct {
	*onet.TreeNode
	dbfv.PCKSShare
}

type StructPublicKey struct {
	*onet.TreeNode
	bfv.PublicKey
}

type StructSk struct {
	*onet.TreeNode
	SK
}

type SK struct {
	SecretKey string
}
type StructCKSShare struct {
	*onet.TreeNode
	dbfv.CKSShare
}

type SwitchingParameters struct {
	Params bfv.Parameters
	//also need skIn, skOut
	SkInputHash  string
	SkOutputHash string
	bfv.Ciphertext
}


type StructSwitchParameters struct {
	*onet.TreeNode
	SwitchingParameters
}

type StructCiphertext struct {
	*onet.TreeNode
	bfv.Ciphertext
}

//type CollectiveKeyShare struct {
//	dbfv.CKGShare
//}

type StructParameters struct {
	*onet.TreeNode
	Params bfv.Parameters
}

type StructPublicKeyShare struct {
	*onet.TreeNode
	dbfv.CKGShare
}


//Wrapper around crp
type CRP struct{
	A [][]*ring.Poly
}


//This message is used to wake up the children
type Start struct{}

type StructStart struct{
	*onet.TreeNode
	Start
}

