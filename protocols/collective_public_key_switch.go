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
	"lattigo-smc/utils"
)

//const ProtocolName = "CollectivePublicKeySwitching"

//NewCollectivePublicKeySwitching initialize a new protocol, register the channels for onet.
func NewCollectivePublicKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectivePublicKeySwitchingProtocol{
		TreeNodeInstance: n,
	}

	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelCiphertext, &p.ChannelPCKS); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//CollectivePublicKeySwitching runs the protocol , returns the ciphertext after key switching and error if there is any.
func (pcks *CollectivePublicKeySwitchingProtocol) CollectivePublicKeySwitching() (*bfv.Ciphertext, error) {

	bfvCtx, _ := bfv.NewBfvContextWithParam(&pcks.Params)
	protocol := dbfv.NewPCKSProtocol(bfvCtx, pcks.Params.Sigma)
	//Round 1
	share := protocol.AllocateShares()
	SecretKey, err := utils.GetSecretKey(bfvCtx, pcks.Sk.SecretKey+pcks.ServerIdentity().String())
	if err != nil {
		log.Error("Error on loading secret key : ", err)
	}
	protocol.GenShare(SecretKey.Get(), &pcks.PublicKey, &pcks.Ciphertext, share)

	for _ = range pcks.Children() {
		log.Lvl1("Getting a child PCKSShare")
		children := (<-pcks.ChannelPCKS).PCKSShare
		protocol.AggregateShares(children, share, share)

	}

	//send the share to the parent..
	log.Lvl1("Sending my PCKSShare")
	err = pcks.SendToParent(&share)
	if err != nil {
		return &bfv.Ciphertext{}, err
	}

	//check if its the root then aggregate else wait on the parent.
	cipher := bfvCtx.NewCiphertext(pcks.Ciphertext.Degree())
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

	return cipher, nil
}
