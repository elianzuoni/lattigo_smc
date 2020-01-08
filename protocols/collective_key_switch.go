// Collective key switching runs the collective key switching protocol
// This allows to change the key under which a cipher is encrypted.
// The nodes need to have shards of the secret key towards which the cipher is going to be encrypted
// 0. Set-up get the parameters and the secret key shards
// 1. Generate the collective key switching share (ckss) locally
// 2. Aggregate the ckss from the children
// 3. Send the ckss to the parent
// 4. Root switches the key under which the cipher is encrypted and sends it to the children
// 5. Get resulting ciphertext from parent and forward to children

package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"sync"
)

const CollectiveKeySwitchingProtocolName = "CollectiveKeySwitching"

func init() {
	_, err := onet.GlobalProtocolRegister(CollectiveKeySwitchingProtocolName, NewCollectiveKeySwitching)
	if err != nil {
		log.ErrFatal(err, "Could not register CollectiveKeySwitching protocol:")
	}
}

//Init initialize the variables needed for the protocol. Should be called before dispatch
func (cks *CollectiveKeySwitchingProtocol) Init(params *bfv.Parameters, skInput *bfv.SecretKey, skOutput *bfv.SecretKey, ciphertext *bfv.Ciphertext) error {
	sp := SwitchingParameters{}
	sp.Params = params.Copy()
	sp.Ciphertext = *ciphertext
	cks.Params = sp

	//Set up the protocol
	cks.CKSProtocol = dbfv.NewCKSProtocol(params, cks.Params.Params.Sigma)
	cks.CKSShare = cks.CKSProtocol.AllocateShare()
	cks.CiphertextOut = bfv.NewCiphertext(params, sp.Ciphertext.Degree())
	cks.CKSProtocol.GenShare(skInput.Get(), skOutput.Get(), &cks.Params.Ciphertext, cks.CKSShare)

	return nil
}

//NewCollectiveKeySwitching initializes a new collective key switching , registers the channels in onet
func NewCollectiveKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectiveKeySwitchingProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
	}

	if e := p.RegisterChannels(&p.ChannelCKSShare, &p.ChannelCiphertext, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//Start starts the protocol only at root
func (cks *CollectiveKeySwitchingProtocol) Start() error {
	log.Lvl4(cks.ServerIdentity(), "Starting collective key switching for key : ", cks.Params)
	//find a way to take advantage of the unmarshalin

	return nil

}

//Dispatch is called at each node to then run the protocol
func (cks *CollectiveKeySwitchingProtocol) Dispatch() error {
	d, _ := cks.Params.Ciphertext.MarshalBinary()
	log.Lvl2("ORIGINAL CIPHER :", d[0:25])
	//Wake up the nodes
	log.Lvl2("Sending wake up message")
	err := cks.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	//start the key switching

	if !cks.IsLeaf() {

		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelCKSShare
			log.Lvl4(cks.ServerIdentity(), " : aggregating !  ")

			//aggregate
			share := child.CKSShare
			cks.CKSProtocol.AggregateShares(share, cks.CKSShare, cks.CKSShare)

		}

	}

	//send to parent.
	err = cks.SendToParent(cks.CKSShare)
	if err != nil {
		return err
	}

	//Now the root can do the keyswitching.
	if cks.IsRoot() {
		log.Lvl2("Root doing key switching ! ")
		cks.CKSProtocol.KeySwitch(cks.CKSShare, &cks.Params.Ciphertext, cks.CiphertextOut)
		d, _ = cks.CiphertextOut.MarshalBinary()
		log.Lvl2("RESULT CIPHER :", d[0:25])

	}

	cks.Cond.Broadcast()
	cks.Done()

	return nil

}

//Wait blocks until the protocol completes.
func (cks *CollectiveKeySwitchingProtocol) Wait() {
	cks.Cond.L.Lock()
	cks.Cond.Wait()
	cks.Cond.L.Unlock()
}
