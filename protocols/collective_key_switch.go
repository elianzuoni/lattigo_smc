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
	"lattigo-smc/utils"
)

//NewCollectiveKeySwitching initializes a new collective key switching , registers the channels in onet
func NewCollectiveKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectiveKeySwitchingProtocol{
		TreeNodeInstance: n,
	}

	if e := p.RegisterChannels(&p.ChannelCKSShare, &p.ChannelCiphertext, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//we use the same parameters as from the collective key generation

//CollectiveKeySwitching runs the collective key switching protocol returns the ciphertext after switching its key and error if there is any
func (cks *CollectiveKeySwitchingProtocol) CollectiveKeySwitching() (*bfv.Ciphertext, error) {

	bfvContext, err := bfv.NewBfvContextWithParam(&cks.Params.Params)

	SkInput, err := utils.GetSecretKey(bfvContext, cks.Params.SkInputHash+cks.ServerIdentity().String())

	SkOutput, err := utils.GetSecretKey(bfvContext, cks.Params.SkOutputHash+cks.ServerIdentity().String())

	if err != nil {
		return &bfv.Ciphertext{}, err
	}

	keySwitch := dbfv.NewCKSProtocol(bfvContext, cks.Params.Params.Sigma)
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
	err = cks.SendToParent(&h)
	if err != nil {
		return nil, err
	}

	//propagate the cipher text.
	//the root propagates the cipher text to everyone.

	res := bfvContext.NewCiphertext(cks.Params.Ciphertext.Degree())
	if cks.IsRoot() {

		keySwitch.KeySwitch(h, &cks.Params.Ciphertext, res)
	} else {
		log.Lvl4("Waiting on cipher text ")
		val := <-cks.ChannelCiphertext
		//log.Print(cks.ServerIdentity(), " : " , val.Ciphertext)
		res = &val.Ciphertext // receive final cipher from parents.

	}

	err = cks.SendToChildren(res)
	// forward the resulting ciphertext to the children
	if err != nil {
		log.Print("Error sending it to children")
		return res, err
	}

	log.Lvl4(cks.ServerIdentity(), "Done with my job ")
	return res, nil
}
