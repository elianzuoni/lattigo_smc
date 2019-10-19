package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
)

func NewPublicCollectiveKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &PublicCollectiveKeySwitchingProtocol{
		TreeNodeInstance: n,
	}

	if e := p.RegisterChannels(&p.ChannelParams, &p.ChannelPublicKey, &p.ChannelSk, &p.ChannelCiphertext, &p.ChannelPCKS); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

func (pcks *PublicCollectiveKeySwitchingProtocol) PublicCollectiveKeySwitching() (*bfv.Ciphertext, error) {
	//TODO modify there is 2 SK ...
	if pcks.IsRoot() {
		log.Lvl1("I have : ", pcks.Sk)
	}
	pcks.Params = (<-pcks.ChannelParams).Params
	log.Lvl4(pcks.ServerIdentity(), "ok params")
	v := (<-pcks.ChannelSk)
	pcks.Sk = v.SK
	log.Lvl4(pcks.ServerIdentity(), "ok string")

	pcks.Ciphertext = (<-pcks.ChannelCiphertext).Ciphertext
	log.Lvl4(pcks.ServerIdentity(), "ok cipher")
	pcks.PublicKey = (<-pcks.ChannelPublicKey).PublicKey
	log.Lvl4(pcks.ServerIdentity(), "ok public key ")
	//log.Lvl4(pcks.ServerIdentity(), " : " , pcks.PublicKey.Get()[0].Coeffs[0][0:25])

	////send them to children..
	err := pcks.SendToChildren(&pcks.Params)
	if err != nil {
		log.Fatal("error on sending parameter to children : ", err)
	}
	sending := pcks.Sk
	err = pcks.SendToChildren(&sending)
	if err != nil {
		log.Fatal("error on sending parameter to children : ", err)
	}

	err = pcks.SendToChildren(&pcks.Ciphertext)
	if err != nil {
		log.Fatal("error on sending parameter to children : ", err)
	}
	err = pcks.SendToChildren(&pcks.PublicKey)
	if err != nil {
		log.Fatal("error on sending parameter to children : ", err)
	}

	//we got all the params now do the first round..
	bfvCtx, _ := bfv.NewBfvContextWithParam(&pcks.Params)
	protocol := dbfv.NewPCKSProtocol(bfvCtx, pcks.Params.Sigma)
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
		res := (<-pcks.ChannelCiphertext)
		cipher = &res.Ciphertext
	}

	//send the result to your child
	d, _ := cipher.MarshalBinary()
	log.Lvl1("FINAL CIPHER : ", d[0:25])
	log.Lvl1("Sending final cipher text ! ")
	err = pcks.SendToChildren(cipher)
	if err != nil {
		return &bfv.Ciphertext{}, err
	}

	return cipher, nil
}
