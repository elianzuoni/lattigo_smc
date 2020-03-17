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
	*dbfv.CKGProtocol
	*sync.Cond

	//Params parameters of the protocol
	Params *bfv.Parameters
	//Secret key of the protocol
	Sk *bfv.SecretKey

	// Public key CRP
	CKG1 *ring.Poly

	// Public key share in the protocol
	CKGShare dbfv.CKGShare

	//Public key generated in the protocol
	Pk *bfv.PublicKey

	Initialized chan bool

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
	*dbfv.CKSProtocol
	*sync.Cond
	//Params used for the key switching
	Params        SwitchingParameters
	CKSShare      dbfv.CKSShare
	CiphertextOut *bfv.Ciphertext

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
	Sk bfv.SecretKey

	bfv.Ciphertext

	PublicKeySwitchProtocol *dbfv.PCKSProtocol
	PCKSShare               dbfv.PCKSShare
	CiphertextOut           bfv.Ciphertext

	*sync.Cond

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
	//CRP the random ring used during the round 1
	Crp CRP
	//SK the secret key of the party
	Sk bfv.SecretKey

	*sync.Cond
	RelinProto      *dbfv.RKGProtocol
	RoundOneShare   dbfv.RKGShareRoundOne
	RoundTwoShare   dbfv.RKGShareRoundTwo
	RoundThreeShare dbfv.RKGShareRoundThree
	U               *ring.Poly
	EvaluationKey   *bfv.EvaluationKey

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

//RefreshProtocol handler for onet for the refresh protocol
type RefreshProtocol struct {
	*onet.TreeNodeInstance

	*sync.Cond

	Sk              bfv.SecretKey
	Ciphertext      bfv.Ciphertext
	FinalCiphertext bfv.Ciphertext
	CRS             ring.Poly
	Params          bfv.Parameters
	RShare          dbfv.RefreshShare

	RefreshProto *dbfv.RefreshProtocol

	ChannelCiphertext chan StructCiphertext
	ChannelRShare     chan StructRShare
	ChannelStart      chan StructStart
}

//RotationKeyProtocol handler for onet for the rotaiton key protocol
type RotationKeyProtocol struct {
	*onet.TreeNodeInstance
	*sync.Cond

	Params           bfv.Parameters
	RotationProtocol *dbfv.RTGProtocol
	RTShare          dbfv.RTGShare
	RotKey           bfv.RotationKeys

	Crp []*ring.Poly

	ChannelRTShare chan StructRTGShare
	ChannelStart   chan StructStart
}

// EncryptionToSharesProtocol implements the onet.Protocol interface.
// Contains all the variables that the caller needs to supply at some phase of the protocol,
// plus the private channels to communicate between nodes, and the public channel to output the result.
type EncryptionToSharesProtocol struct {
	*onet.TreeNodeInstance
	*dbfv.E2SProtocol

	//Variables not contained in E2SProtocol.
	sk *bfv.SecretKey
	ct *bfv.Ciphertext

	//Channels to receive from other nodes.
	channelStart     chan StructStart
	channelDecShares chan []StructE2SDecryptionShare //A channel of slices allows to receive all shares at once

	//Channel to return the additive share to caller
	ChannelAddShare chan dbfv.AdditiveShare
}

// SharesToEncryptionProtocol implements the onet.Protocol interface.
// Contains all the variables that the caller needs to supply at some phase of the protocol,
// plus the private channels to communicate between nodes, and the public channel to output the result.
type SharesToEncryptionProtocol struct {
	*onet.TreeNodeInstance
	*dbfv.S2EProtocol

	//Variables not contained in E2SProtocol.
	addShare dbfv.AdditiveShare
	sk       *bfv.SecretKey
	crs      *ring.Poly

	//Channels to receive from other nodes.
	channelStart       chan StructStart
	channelReencShares chan []StructS2EReencryptionShare //A channel of slices allows to receive all shares at once

	//Channel to return the ciphertext to the caller (only if root)
	ChannelCiphertext chan *bfv.Ciphertext
}

//StructRTGShare handler for onet
type StructRTGShare struct {
	*onet.TreeNode
	dbfv.RTGShare
}

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

//StructRSahre handler for the refresh share.
type StructRShare struct {
	*onet.TreeNode
	dbfv.RefreshShare
}

//StructCiphertext handler for onet
type StructCiphertext struct {
	*onet.TreeNode
	bfv.Ciphertext
}

//StructSwitchParameters handler for onet
type StructSwitchParameters struct {
	*onet.TreeNode
	SwitchingParameters
}

//SwitchingParameters contains the public parameters for CKS
type SwitchingParameters struct {
	//Params parameters bfv
	Params *bfv.Parameters

	bfv.Ciphertext
}

//StructCKSShare handler for onet
type StructCKSShare struct {
	*onet.TreeNode
	dbfv.CKSShare
}

//StructPCKS handler for onet
type StructPCKS struct {
	*onet.TreeNode
	dbfv.PCKSShare
}

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

// StructE2SDecryptionShare is a handler for onet.
// Wraps the decryption share (used in Encryption-to-Shares protocol) so that it can
// be passed via onet with the paradigm described in cothority_template
type StructE2SDecryptionShare struct {
	*onet.TreeNode
	dbfv.E2SDecryptionShare
}

// StructE2SReencryptionShare is a handler for onet.
// Wraps the re-encryption share (used in Shares-to-Encryption protocol) so that it can
// be passed via onet with the paradigm described in cothority_template
type StructS2EReencryptionShare struct {
	*onet.TreeNode
	dbfv.S2EReencryptionShare
}
