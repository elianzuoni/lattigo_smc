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
	"sync"
)

const CollectivePublicKeySwitchingProtocolName = "CollectivePublicKeySwitching"

func init() {
	_, _ = onet.GlobalProtocolRegister(CollectivePublicKeySwitchingProtocolName, NewCollectivePublicKeySwitching)
}

//NewCollectivePublicKeySwitching initialize a new protocol, register the channels for onet.
func NewCollectivePublicKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectivePublicKeySwitchingProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
	}

	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelCiphertext, &p.ChannelPCKS); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

/*********ONET HANDLERS*************/

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
	log.Lvl4("Dispatching ! ")
	res, err := pcks.CollectivePublicKeySwitching()

	if err != nil {
		log.Fatal("Error : ", err)
	}

	if Test() {
		//If test send to root again so we can check at the test program
		_ = pcks.SendTo(pcks.Root(), res)
	}

	if !pcks.IsRoot() && Test() {
		pcks.Done()
	}

	return nil

}

func (pcks *CollectivePublicKeySwitchingProtocol) Wait() {
	pcks.Cond.L.Lock()
	pcks.Cond.Wait()
	pcks.Cond.L.Unlock()
}

//CollectivePublicKeySwitching runs the protocol , returns the ciphertext after key switching and error if there is any.
func (pcks *CollectivePublicKeySwitchingProtocol) CollectivePublicKeySwitching() (*bfv.Ciphertext, error) {

	params := pcks.Params
	protocol := dbfv.NewPCKSProtocol(&params, pcks.Params.Sigma)
	//Round 1
	share := protocol.AllocateShares()
	SecretKey := pcks.Sk

	protocol.GenShare(SecretKey.Get(), &pcks.PublicKey, &pcks.Ciphertext, share)

	for range pcks.Children() {
		log.Lvl3("Getting a child PCKSShare")
		children := (<-pcks.ChannelPCKS).PCKSShare
		protocol.AggregateShares(children, share, share)

	}

	//send the share to the parent..
	log.Lvl3("Sending my PCKSShare")
	err := pcks.SendToParent(&share)
	if err != nil {
		return &bfv.Ciphertext{}, err
	}

	//check if its the root then aggregate else wait on the parent.
	cipher := bfv.NewCiphertext(&params, pcks.Ciphertext.Degree())
	if pcks.IsRoot() {
		protocol.KeySwitch(share, &pcks.Ciphertext, cipher)
	} else {
		res := <-pcks.ChannelCiphertext
		cipher = &res.Ciphertext
	}

	//send the result to your child
	d, _ := cipher.MarshalBinary()
	log.Lvl4("FINAL CIPHER : ", d[0:25])
	log.Lvl4("Sending final cipher text ! ")
	err = pcks.SendToChildren(cipher)
	if err != nil {
		return &bfv.Ciphertext{}, err
	}

	pcks.Cond.Broadcast()

	return cipher, nil
}
