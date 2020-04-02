//Collective public key switching allows to change the key under which a key is encrypted.
// The node needs to only know the public key of the resulting cipher text.
// 1. Allocate the shares and generate i t
// 2. Aggregate the shares from the children
// 3. Forward them to the parent
// 4. Root performs the key switching and sends the resulting cipher text to its children
// 5. get the result from parents and forward it to the children.

package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

const CollectivePublicKeySwitchingProtocolName = "CollectivePublicKeySwitching"

func init() {
	_, _ = onet.GlobalProtocolRegister(CollectivePublicKeySwitchingProtocolName, NewCollectivePublicKeySwitching)
}

//Init initializes the protocol and prepares the variable. Should be called before dispatch
func (pcks *CollectivePublicKeySwitchingProtocol) Init(params bfv.Parameters, publicKey bfv.PublicKey, sk bfv.SecretKey, ciphertext *bfv.Ciphertext) error {
	pcks.Params = params
	pcks.Sk = sk
	pcks.PublicKey = publicKey
	pcks.Ciphertext = *ciphertext
	pcks.CiphertextOut = *bfv.NewCiphertext(&params, ciphertext.Degree())

	//Protocol
	pcks.PublicKeySwitchProtocol = dbfv.NewPCKSProtocol(&params, params.Sigma)
	pcks.PCKSShare = pcks.PublicKeySwitchProtocol.AllocateShares()
	pcks.PublicKeySwitchProtocol.GenShare(sk.Get(), &publicKey, ciphertext, pcks.PCKSShare)

	return nil

}

//NewCollectivePublicKeySwitching initialize a new protocol, register the channels for onet.
func NewCollectivePublicKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectivePublicKeySwitchingProtocol{
		TreeNodeInstance: n,
	}

	p.done.Lock()

	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelPCKS); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//Start starts the protocol only at root
func (pcks *CollectivePublicKeySwitchingProtocol) Start() error {
	log.Lvl2(pcks.ServerIdentity(), " starting public collective key switching with parameters : ", pcks.Params)

	return nil

}

//Dispatch is called at each node to then run the protocol
func (pcks *CollectivePublicKeySwitchingProtocol) Dispatch() error {

	err := pcks.SendToChildren(&Start{})
	if err != nil {
		log.Error("Could not send start message  : ", err)
		return err
	}

	for range pcks.Children() {
		log.Lvl3("Getting a child PCKSShare")
		children := (<-pcks.ChannelPCKS).PCKSShare
		pcks.PublicKeySwitchProtocol.AggregateShares(children, pcks.PCKSShare, pcks.PCKSShare)

	}

	//send the share to the parent..
	log.Lvl3("Sending my PCKSShare")
	err = pcks.SendToParent(&pcks.PCKSShare)
	if err != nil {
		return err
	}

	//check if its the root then aggregate else wait on the parent.
	if pcks.IsRoot() {
		pcks.PublicKeySwitchProtocol.KeySwitch(pcks.PCKSShare, &pcks.Ciphertext, &pcks.CiphertextOut)
	}

	pcks.done.Unlock()

	pcks.Done()

	return nil

}

/*********************** Not onet handlers ************************/

// By calling this method, the root can wait for termination of the protocol.
// It is safe to call multiple times.
func (p *CollectivePublicKeySwitchingProtocol) WaitDone() {
	log.Lvl3("Waiting for protocol to end")
	p.done.Lock()
	// Unlock again so that subsequent calls to WaitDone do not block forever
	p.done.Unlock()
}
