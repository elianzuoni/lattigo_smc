// Shares-to-encryption protocol: the parties switch from an additive-secret-shared to an encrypted plaintext.
// Unlike the encryption-to-shares protocol, the root is not special (except for the fact that it is the only one
// that, at the end, actually has the plaintext).
// The steps are:
//
// Method Init:
// 0) Every node initialises the protocol variables.
// Method Start:
// 1) The root sends the wake-up message to itself.
// Method Dispatch
// 2) Every node waits to receive the wake-up message, then re-sends it to children.
// 3a) Every node computes its re-encryption share.
//		3b) If node is not leaf, it waits to collect re-encryption shares from every child
//		 	and aggregate them.
// 3c) Every node sends the (aggregated) re-encryption share to the parent.
// 4) If node is root, computes the ciphertext and returns it (non-roots return nothing).

package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

//CollectiveKeyGenerationProtocolName name of protocol for onet.
const SharesToEncryptionProtocolName = "SharesToEncryption"

// init registers the protocol to the underlying onet library, so that it has a factory
// when it has to instantiate a ProtocolInstance
func init() {

	if _, err := onet.GlobalProtocolRegister(SharesToEncryptionProtocolName, NewSharesToEncryptionProtocol); err != nil {
		log.ErrFatal(err, "Could not register EncryptionToShares protocol : ")
	}

}

// NewSharesToEncryptionProtocol is called when a new protocol is started (at the root) or
// when a message is received for a new instance of the protocol (at non-roots).
// It only initialises with the onet-related variables: the channels and the TreeNodeInstance;
// the rest has to be "manually" initialised through Init.
func NewSharesToEncryptionProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1("NewEncryptionToSharesProtocol called")

	p := &SharesToEncryptionProtocol{
		TreeNodeInstance: n,
	}

	//No need to initialise the channels: onet.RegisterChannels will do it for us.
	if e := p.RegisterChannels(&p.channelStart, &p.channelReencShares); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

// NewEncryptionToSharesProtocol is called when a new protocol is started (at the root) or
// when a message is received for a new instance of the protocol (at non-roots).
// It only initialises with the onet-related variables: the channels and the TreeNodeInstance;
// the rest has to be "manually" initialised through Init.
func (p *SharesToEncryptionProtocol) Init(params *bfv.Parameters, sigmaSmudging float64,
	addShare dbfv.AdditiveShare, sk *bfv.SecretKey, crs *ring.Poly) error {
	p.S2EProtocol = dbfv.NewS2EProtocol(params, sigmaSmudging)

	p.addShare = addShare
	p.sk = sk
	p.crs = crs

	p.ChannelCiphertext = make(chan *bfv.Ciphertext)

	return nil
}

/****************ONET HANDLERS ******************/

//Start starts the protocol (only called at root).
func (p *SharesToEncryptionProtocol) Start() error {
	log.Lvl2(p.ServerIdentity(), "Started Encryption-to-Shares protocol")
	//Step 1: send wake-up message to self
	return p.SendTo(p.TreeNode(), &Start{})
}

// Dispatch is called at each node to run the protocol.
// It implements the main protocol logic.
func (p *SharesToEncryptionProtocol) Dispatch() error {
	var reencShare dbfv.S2EReencryptionShare          // Will be sent to parent
	var childReencShares []StructS2EReencryptionShare //Will contain children's re-encryption shares
	var cipher *bfv.Ciphertext                        //Will be returned to caller via ChannelAddShare

	reencShare = p.AllocateShare()

	log.Lvl3(p.ServerIdentity(), " Dispatching ; is root = ", p.IsRoot())

	// Step 2: wait for wake-up, then send it to children
	log.Lvl3("Waiting for wake-up message")
	wakeup := <-p.channelStart
	//Send wake-up message to all children
	log.Lvl3("Sending wake-up message")
	err := p.SendToChildren(&wakeup)
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
		return err
	}

	// Step 3: case leaf / non-leaf.
	// Step 3a: compute re-encryption share.
	p.GenShare(p.sk, p.crs, p.addShare, reencShare)
	// Step 3b: if non-leaf, wait and aggregate children's shares
	if !p.IsLeaf() {
		childReencShares = <-p.channelReencShares
		for _, share := range childReencShares {
			p.AggregateShares(reencShare, share.S2EReencryptionShare, reencShare)
		}
	}
	// Step 3c: send to parent (has no effect if node is root).
	if err = p.SendToParent(&reencShare); err != nil {
		log.ErrFatal(err, "Could not re-encryption share to parent ")
		return err
	}

	// Step 4: if root, compute ciphertext
	if p.IsRoot() {
		cipher = p.Reencrypt(reencShare, p.crs)
	} else {
		cipher = nil
	}
	// Return in any case
	p.ChannelCiphertext <- cipher

	p.Done() //Onet requirement to finalise the protocol

	return nil
}
