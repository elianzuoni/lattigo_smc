//Encryption-to-shares protocol: the parties switch from an encrypted to an additive-secret-shared plaintext.
//The root is special (it is the "master" defined in dbfv): it aggregates decryption shares by the other nodes
//to produce its own additive share, it does not generate any decryption share.
//The steps are:
//
// Method NewEncryptionToSharesProtocol:
// 0) The nodes initialise the variables needed for the protocol. This method is not usable as-is: it
//    needs to be encapsulated in a proper protocol factory (respecting the onet.NewProtocol signature).
//    For this reason, though EncryptionToSharesProtocol does implement the onet.ProtocolInstance interface,
//    it is not registered to the onet library, as no protocol factory is yet defined.
// Method Start:
// 1) The root sends the wake-up message to itself.
// Method Dispatch
// 2) Every node waits to receive the wake-up message, then re-sends it to children.
// 		3a) If node is a leaf, it computes its decryption share, and sends it to its parent.
//		3b) Else, if not root, it computes its own decryption share, waits to receive it from every child,
//		    aggregates them, and sends to parent.
//		3c) If root, only the additive share is generated by the combined decryption share
// 4) In any case, the additive share is returned by feeding it to the finaliser.

// As an architectural choice, the channel for the final output of the protocol (the AdditiveShare)
// is here replaced by a "finalise" function: this is because this is the only protocol that provides an
// output to all the parties, not just to the caller (the root). But non-roots are unaware that the protocol
// is even being run, so they have no way to predispose a goroutine that listens on the output channel, because
// it doesn't know which channel to listen on. A possible choice for the finalise function would be to forward
// the AdditiveShare to a channel another goroutine is already listening on; alternatively, the finalise function
// could directly do what the listener would do anyway, like putting the share into a map, logging it, and so on.

package protocols

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/utils"
)

func init() {
	fmt.Println("E2S: init")

	_ = network.RegisterMessage(Start{})
	_ = network.RegisterMessage(dbfv.E2SDecryptionShare{})
}

// This is a full-blown constructor. In every context (test, simulation, or deployment) it will have to
// be encapsulated in a proper protocol factory, that only takes the TreeNodeInstance as an argument
// and somehow supplies the rest of the parameters on its own.
func NewEncryptionToSharesProtocol(t *onet.TreeNodeInstance, params *bfv.Parameters, sigmaSmudging float64,
	sk *bfv.SecretKey, ct *bfv.Ciphertext, finalise func(*dbfv.AdditiveShare)) (*EncryptionToSharesProtocol, error) {
	proto := &EncryptionToSharesProtocol{
		TreeNodeInstance: t,
		E2SProtocol:      dbfv.NewE2SProtocol(params, sigmaSmudging),
		sk:               sk,
		ct:               ct,
		finalise:         finalise,
		// No need to initialise the Mutex
	}

	// The zero value of a Mutex is an unlocked one.
	proto.done.Lock()

	// No need to initialise the channels: RegisterChannels will do it for us.
	if err := proto.RegisterChannels(&proto.channelStart, &proto.channelDecShares); err != nil {
		log.Fatal("Could not register channels: ", err)
		return nil, err
	}

	return proto, nil
}

/****************ONET HANDLERS ******************/

//Start starts the protocol (only called at root).
func (p *EncryptionToSharesProtocol) Start() error {
	log.Lvl2(p.ServerIdentity(), "Started Encryption-to-Shares protocol")
	//Step 1: send wake-up message to self
	return p.SendTo(p.TreeNode(), &Start{})
}

// Dispatch is called at each node to run the protocol.
// It implements the main protocol logic.
func (p *EncryptionToSharesProtocol) Dispatch() error {
	var decShare *dbfv.E2SDecryptionShare         // Will be sent to parent
	var childDecShares []StructE2SDecryptionShare //Will contain children's decryption shares
	var addShare *dbfv.AdditiveShare              //Will be returned to caller via ChannelAddShare

	decShare, addShare = p.AllocateShares()

	log.Lvl3(p.ServerIdentity(), "Started dispatching")

	// Step 2: wait for wake-up, then send it to children
	log.Lvl3(p.ServerIdentity(), "Waiting for wake-up message")
	wakeup := <-p.channelStart
	//Send wake-up message to all children
	log.Lvl3(p.ServerIdentity(), "Sending wake-up message")
	err := p.SendToChildren(&wakeup.Start)
	if err != nil {
		log.ErrFatal(err, p.ServerIdentity(), "Could not send wake up message: ")
		return err
	}

	// Step 3: case leaf / intermediate / root.
	if p.IsLeaf() {
		// Step 3a: generate decryption share, then send it to parent.
		p.GenSharesSlave(p.sk, p.ct, decShare, addShare)
		log.Lvl3(p.ServerIdentity(), "Leaf. Generated decryption share: sending to parent")
		if err = p.SendToParent(decShare); err != nil {
			log.ErrFatal(err, p.ServerIdentity(), "Could not send decryption share to parent: ")
			return err
		}
	} else if !p.IsRoot() {
		// Step 3b: generate decryption share, then wait for children's share,
		// then aggregate, then send to parent.
		p.GenSharesSlave(p.sk, p.ct, decShare, addShare)
		log.Lvl3(p.ServerIdentity(), "Non-leaf, non-root. Generated decryption share: waiting to collect children's shares")
		childDecShares = <-p.channelDecShares // Blocking wait.

		log.Lvl3(p.ServerIdentity(), "Non-leaf, non-root. Received children's shares: aggregating")
		for _, share := range childDecShares {
			p.AggregateDecryptionShares(decShare, &share.E2SDecryptionShare, decShare)
		}

		log.Lvl3(p.ServerIdentity(), "Non-leaf, non-root. Aggregated children's shares: sending to parent")
		if err = p.SendToParent(decShare); err != nil {
			log.ErrFatal(err, p.ServerIdentity(), "Could not send decryption share to parent ")
			return err
		}
	} else {
		// Step 3c: wait for children's share, then aggregate, then generate additive share
		log.Lvl3(p.ServerIdentity(), "Root. Waiting to receive children's shares")
		childDecShares = <-p.channelDecShares // Blocking wait.

		log.Lvl3(p.ServerIdentity(), "Root. Received children's shares: aggregating")
		for _, share := range childDecShares {
			p.AggregateDecryptionShares(decShare, &share.E2SDecryptionShare, decShare)
		}

		log.Lvl3(p.ServerIdentity(), "Root. Aggregated children's shares: generating mine")
		p.GenShareMaster(p.sk, p.ct, decShare, addShare)
	}

	log.Lvl3(p.ServerIdentity(), "Finalising AdditiveShare")
	// Step 4: return the generated additive by feeding it to the finalise
	p.finalise(addShare)
	// Also signal that the protocol is finished
	p.done.Unlock()

	p.Done() // Onet requirement to finalise the protocol.

	return nil
}

/*********************** Not onet handlers ************************/

// By calling this method, the root can wait for termination of the protocol.
// It is safe to call multiple times.
func (p *EncryptionToSharesProtocol) WaitDone() {
	log.Lvl3("Waiting for protocol to end")
	p.done.Lock()
	// Unlock again so that subsequent calls to WaitDone do not block forever
	p.done.Unlock()
}

// Check that *EncryptionToSharesProtocol implements onet.ProtocolInstance
var _ onet.ProtocolInstance = (*EncryptionToSharesProtocol)(nil)

// NewE2SAccumFinaliser returns a finaliser which is recurrent in tests: it accumulates to the provided accumulator.
func NewE2SAccumFinaliser(accum *utils.ConcurrentAdditiveShareAccum) func(share *dbfv.AdditiveShare) {
	return func(share *dbfv.AdditiveShare) {
		accum.Accumulate(share)
	}
}
