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
	_, _ = onet.GlobalProtocolRegister(CollectiveKeySwitchingProtocolName, NewCollectiveKeySwitching)
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

/************ONET HANDLERS ********************/
//Start starts the protocol only at root
func (cks *CollectiveKeySwitchingProtocol) Start() error {
	log.Lvl4(cks.ServerIdentity(), "Starting collective key switching for key : ", cks.Params)
	//find a way to take advantage of the unmarshalin

	//cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(), SwitchingParameters{cks.Params.Params, cks.Params.SkInputHash, cks.Params.SkOutputHash, cks.Params.Ciphertext}}

	return nil

}

//Dispatch is called at each node to then run the protocol
func (cks *CollectiveKeySwitchingProtocol) Dispatch() error {

	//Wake up the nodes
	log.Lvl2("Sending wake up message")
	err := cks.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	//start the key switching
	d, _ := cks.Params.Ciphertext.MarshalBinary()
	log.Lvl2("ORIGINAL CIPHER :", d[0:25])
	res, err := cks.CollectiveKeySwitching()
	if err != nil {
		return err
	}
	d, _ = res.MarshalBinary()
	log.Lvl4(cks.ServerIdentity(), " : Resulting ciphertext - ", d[0:25])
	//send it back when testing to check...

	if Test() {
		err := cks.SendTo(cks.Root(), res)
		if err != nil {
			return nil
		}
		if !cks.IsRoot() {
			cks.Done()
		}
	}
	cks.Cond.Broadcast()

	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Wait() {
	cks.Cond.L.Lock()
	cks.Cond.Wait()
	cks.Cond.L.Unlock()
}

//CollectiveKeySwitching runs the collective key switching protocol returns the ciphertext after switching its key and error if there is any
func (cks *CollectiveKeySwitchingProtocol) CollectiveKeySwitching() (*bfv.Ciphertext, error) {

	params := cks.Params.Params
	SkInput := cks.Params.SkInput

	SkOutput := cks.Params.SkOutput

	keySwitch := dbfv.NewCKSProtocol(&params, cks.Params.Params.Sigma)
	h := keySwitch.AllocateShare()

	keySwitch.GenShare(SkInput.Get(), SkOutput.Get(), &cks.Params.Ciphertext, h)

	if !cks.IsLeaf() {

		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelCKSShare
			log.Lvl4(cks.ServerIdentity(), " : aggregating !  ")

			//aggregate
			share := child.CKSShare
			keySwitch.AggregateShares(share, h, h)

		}

	}

	//send to parent.
	err := cks.SendToParent(&h)
	if err != nil {
		return nil, err
	}

	//propagate the cipher text.
	//the root propagates the cipher text to everyone.

	res := bfv.NewCiphertext(&params, cks.Params.Ciphertext.Degree())
	if cks.IsRoot() {
		log.Lvl2("Root doing key switching ! ")
		keySwitch.KeySwitch(h, &cks.Params.Ciphertext, res)
	} else {
		log.Lvl4("Waiting on cipher text ")
		val := <-cks.ChannelCiphertext
		res = &val.Ciphertext // receive final cipher from parents.

	}

	err = cks.SendToChildren(res)
	// forward the resulting ciphertext to the children
	if err != nil {
		log.Error("Error sending it to children")
		return res, err
	}

	log.Lvl4(cks.ServerIdentity(), "Done with my job ")
	return res, nil
}
