// Shares-to-encryption protocol: the parties switch from an additive-secret-shared to an encrypted plaintext.
// Unlike the encryption-to-shares protocol, the root is not special (except for the fact that it is the only one
// that, at the end, actually has the plaintext).
// The steps are:
//
// Method NewSharesToEncryptionProtocol:
// 0) The nodes initialise the variables needed for the protocol. This method is not usable as-is: it
//    needs to be encapsulated in a proper protocol factory (respecting the onet.NewProtocol signature).
//    For this reason, though SharesToEncryptionProtocol does implement the onet.ProtocolInstance interface,
//    it is not registered to the onet library, as no protocol factory is yet defined.
// Method Start:
// 1) The root sends the wake-up message to itself.
// Method Dispatch:
// 2) Every node waits to receive the wake-up message, then re-sends it to children.
// 3a) Every node computes its re-encryption share.
//		3b) If node is not leaf, it waits to collect re-encryption shares from every child
//		 	and aggregate them.
// 3c) Every node sends the (aggregated) re-encryption share to the parent.
// 4) If node is root, computes the ciphertext and returns it (non-roots return nothing).

package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// This is a full-blown constructor. In every context (test, simulation, or deployment) it will have to
// be encapsulated in a proper protocol factory, that only takes the TreeNodeInstance as an argument
// and somehow supplies the rest of the parameters on its own.
func NewSharesToEncryptionProtocol(t *onet.TreeNodeInstance, params *bfv.Parameters, sigmaSmudging float64,
	addShare *dbfv.AdditiveShare, sk *bfv.SecretKey, crs *ring.Poly) (*SharesToEncryptionProtocol, error) {
	proto := &SharesToEncryptionProtocol{
		TreeNodeInstance: t,
		S2EProtocol:      dbfv.NewS2EProtocol(params, sigmaSmudging),
		addShare:         addShare,
		sk:               sk,
		crs:              crs,
	}

	proto.done.Lock()

	// No need to initialise the channels: RegisterChannels will do it for us.
	err := proto.RegisterChannels(&proto.channelStart, &proto.channelReencShares)

	return proto, err
}

/****************ONET HANDLERS ******************/

//Start starts the protocol (only called at root).
func (p *SharesToEncryptionProtocol) Start() error {
	log.Lvl2(p.ServerIdentity(), "Started Shares-To-Encryption protocol")
	//Step 1: send wake-up message to self
	return p.SendTo(p.TreeNode(), &Start{})
}

// Dispatch is called at each node to run the protocol.
// It implements the main protocol logic.
func (p *SharesToEncryptionProtocol) Dispatch() error {
	var reencShare *dbfv.S2EReencryptionShare         // Will be sent to parent
	var childReencShares []StructS2EReencryptionShare //Will contain children's re-encryption shares

	reencShare = p.AllocateShare()

	log.Lvl3(p.ServerIdentity(), "Started dispatching")

	// Step 2: wait for wake-up, then send it to children
	log.Lvl3(p.ServerIdentity(), "Waiting for wake-up message")
	wakeup := <-p.channelStart
	//Send wake-up message to all children
	log.Lvl3(p.ServerIdentity(), "Sending wake-up message")
	err := p.SendToChildren(&wakeup.Start)
	if err != nil {
		log.ErrFatal(err, p.ServerIdentity(), "Could not send wake up message ")
		return err
	}

	// Step 3: case leaf / non-leaf.
	// Step 3a: compute re-encryption share.
	log.Lvl2(p.ServerIdentity(), "Generating re-encryption share")
	p.GenShare(p.sk, p.crs, p.addShare, reencShare)
	// Step 3b: if non-leaf, wait and aggregate children's shares
	if !p.IsLeaf() {
		log.Lvl3(p.ServerIdentity(), "Non-leaf: waiting to collect children's shares")
		childReencShares = <-p.channelReencShares
		log.Lvl3(p.ServerIdentity(), "Non-leaf: aggregating children's shares")
		for _, share := range childReencShares {
			p.AggregateShares(reencShare, &share.S2EReencryptionShare, reencShare)
		}
	}
	// Step 3c: send to parent (has no effect if node is root).
	log.Lvl3(p.ServerIdentity(), "Sending share to parent")
	if err = p.SendToParent(reencShare); err != nil {
		log.ErrFatal(err, p.ServerIdentity(), "Could not send re-encryption share to parent ")
		return err
	}

	// Step 4: if root, compute ciphertext and return it
	if p.IsRoot() {
		log.Lvl2(p.ServerIdentity(), "Re-encrypting, then sending to output channel")
		p.OutputCiphertext = p.Reencrypt(reencShare, p.crs)
	}

	p.done.Unlock() // Signal that the protocol is finished

	p.Done() // Onet requirement to finalise the protocol

	return nil
}

/*********************** Not onet handlers ************************/

// By calling this method, the root can wait for termination of the protocol.
// It is safe to call multiple times.
func (p *SharesToEncryptionProtocol) WaitDone() {
	log.Lvl3("Waiting for protocol to end")
	p.done.Lock()
	// Unlock again so that subsequent calls to WaitDone do not block forever
	p.done.Unlock()
}
