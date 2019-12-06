//Struct contains all the structure that are used to help with the protocols

package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"sync"
)

//CollectiveKeyGenerationProtocol structure encapsulating a key gen protocol for onet.
type CollectiveKeyGenerationProtocol struct {
	*onet.TreeNodeInstance

	//Params parameters of the protocol
	Params bfv.Parameters
	//Secret key of the protocol
	Sk bfv.SecretKey
	//Public key generated in the protocol
	Pk bfv.PublicKey
	*sync.Cond

	//ChannelPublicKeyShares to send the public key shares
	ChannelPublicKeyShares chan StructPublicKeyShare
	//ChannelPublicKey send the key at the end.
	ChannelPublicKey chan StructPublicKey
	//ChannelStart to get the wake up
	ChannelStart chan StructStart
}

//CollectiveKeySwitchingProtocol struct for onet
type CollectiveKeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	//Params used for the key switching
	Params SwitchingParameters

	//ChannelCiphertext to send the ciphertext in the end - for testing
	ChannelCiphertext chan StructCiphertext
	//ChannelCKSShare to forward the CKSS share
	ChannelCKSShare chan StructCKSShare

	//ChannelStart to wake up
	ChannelStart chan StructStart
}

//CollectivePublicKeySwitchingProtocol Structure for onet for the pcks
type CollectivePublicKeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	//Params bfv parameters.
	Params bfv.Parameters

	bfv.PublicKey
	//SK the secret key hash
	Sk SK

	bfv.Ciphertext

	//ChannelCiphertext to send the ciphertext in the end
	ChannelCiphertext chan StructCiphertext
	//ChannelPCKS to forward the shares.
	ChannelPCKS chan StructPCKS
	//ChannelStart to wake up
	ChannelStart chan StructStart
}

//RelinearizationKeyProtocol handler for onet for RLK
type RelinearizationKeyProtocol struct {
	*onet.TreeNodeInstance
	//Params the bfv parameters
	Params bfv.Parameters
	//Todo have better variable names once its coded.
	//CRP the random ring used during the round 1
	Crp CRP
	//SK the secret key of the party
	Sk SK

	//ChannelRoundOne to send the different parts of the key
	ChannelRoundOne chan StructRelinKeyRoundOne
	//ChannelRoundTwo to send the different parts of the key
	ChannelRoundTwo chan StructRelinKeyRoundTwo
	//ChannelRoundThree to send the different parts of the key
	ChannelRoundThree chan StructRelinKeyRoundThree

	//ChannelEvalKey These are used for testing.
	ChannelEvalKey chan StructEvalKey

	//Chan to wake up nodes
	ChannelStart chan StructStart
}

/********MESSSAGE STRUCTURES ***/

/**USED FOR ALL ***/

//StructParameters handler for onet
type StructParameters struct {
	*onet.TreeNode
	//Params parameters bfv..
	Params bfv.Parameters
}

//StructStart onet handler
type StructStart struct {
	*onet.TreeNode
	Start
}

//Start This message is used to wake up the children
type Start struct{}

/***USED FOR KEY GEN ***/

//StructPublicKey handler for onet
type StructPublicKey struct {
	*onet.TreeNode
	bfv.PublicKey
}

//StructPublicKeyShare handler for onet
type StructPublicKeyShare struct {
	*onet.TreeNode
	dbfv.CKGShare
}

/*****USED FOR BOTH CKS AND PCKS ***/

//StructCiphertext handler for onet
type StructCiphertext struct {
	*onet.TreeNode
	bfv.Ciphertext
}

//StructSk handler for onet
type StructSk struct {
	*onet.TreeNode
	SK
}

//SK encapsulates a hash for a secretkey - useful if you want to retrieve or experiment
type SK struct {
	SecretKey string
}

/***USED FOR CKS **/

//StructSwitchParameters handler for onet
type StructSwitchParameters struct {
	*onet.TreeNode
	SwitchingParameters
}

//SwitchingParameters contains the public parameters for CKS
type SwitchingParameters struct {
	//Params parameters bfv
	Params bfv.Parameters
	//SkInputHash the hash of secret key under which ciphertext is *currently* encrypted
	SkInputHash string
	//SkOutputHash the hash of secretkey under which ciphertext will be encrypted *after* running CKS
	SkOutputHash string
	bfv.Ciphertext
}

//StructCKSShare handler for onet
type StructCKSShare struct {
	*onet.TreeNode
	dbfv.CKSShare
}

/***USED FOR PCKS ***/

//StructPCKS handler for onet
type StructPCKS struct {
	*onet.TreeNode
	dbfv.PCKSShare
}

//***USED FOR RLK ****/

//StructEvalKey handler for onet
type StructEvalKey struct {
	*onet.TreeNode
	bfv.EvaluationKey
}

//StructCrp handler for onet
type StructCrp struct {
	*onet.TreeNode
	CRP
}

//CRP Wrapper around crp
type CRP struct {
	A []*ring.Poly
}

//StructRelinKeyRoundOne handler for onet - used to send the share after round one
type StructRelinKeyRoundOne struct {
	*onet.TreeNode
	dbfv.RKGShareRoundOne
}

//StructRelinKeyRoundTwo handler for onet - used to send share after round two
type StructRelinKeyRoundTwo struct {
	*onet.TreeNode
	dbfv.RKGShareRoundTwo
}

//StructRelinKeyRoundThree handler for onet - used to send share after round thre e
type StructRelinKeyRoundThree struct {
	*onet.TreeNode
	dbfv.RKGShareRoundThree
}
