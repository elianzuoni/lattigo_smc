package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
)

func NewPublicCollectiveKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &PublicCollectiveKeySwitchingProtocol{
		TreeNodeInstance:       n,
	}

	if e := p.RegisterChannels(&p.ChannelParams,  &p.ChannelPublicKey,&p.ChannelSk,&p.ChannelCiphertext,&p.ChannelPCKS); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}




func (pcks *PublicCollectiveKeySwitchingProtocol) PublicCollectiveKeySwitching()(*bfv.Ciphertext,error) {
	if !pcks.IsRoot() {

		pcks.Params = (<-pcks.ChannelParams).Params
		log.Lvl4(pcks.ServerIdentity(), "ok params")
		v := (<-pcks.ChannelSk).SK
		pcks.Sk = v.SecretKey
		log.Lvl4(pcks.ServerIdentity(), "ok string")

		pcks.Ciphertext = (<-pcks.ChannelCiphertext).Ciphertext
		log.Lvl4(pcks.ServerIdentity(), "ok cipher")
		pcks.PublicKey = (<-pcks.ChannelPublicKey).PublicKey
		log.Lvl4(pcks.ServerIdentity(), "ok public key ")
		//log.Lvl4(pcks.ServerIdentity(), " : " , pcks.PublicKey.Get()[0].Coeffs[0][0:25])
	}

	////send them to children..
	err := pcks.SendToChildren(&pcks.Params)
	if err != nil{
		log.Fatal("error on sending parameter to children : " , err)
	}
	sending := SK{SecretKey:pcks.Sk}
	err = pcks.SendToChildren(&sending)
	if err != nil{
		log.Fatal("error on sending parameter to children : " , err)
	}

	err = pcks.SendToChildren(&pcks.Ciphertext)
	if err != nil{
		log.Fatal("error on sending parameter to children : " , err)
	}
	err = pcks.SendToChildren(&pcks.PublicKey)
	if err != nil{
		log.Fatal("error on sending parameter to children : " , err)
	}

	//we got all the params now do the first round..
	bfvCtx,_ := bfv.NewBfvContextWithParam(&pcks.Params)
	protocol := dbfv.NewPCKSProtocol(bfvCtx,pcks.Params.Sigma)
	share := protocol.AllocateShares()
	SecretKey,_ := utils.LoadSecretKey(bfvCtx,pcks.Sk+pcks.ServerIdentity().String())

	protocol.GenShare(SecretKey.Get(),&pcks.PublicKey,&pcks.Ciphertext,share)

	for _ = range pcks.Children(){
		children := (<-pcks.ChannelPCKS).PCKSShare
		protocol.AggregateShares(children,share,share)

	}

	//send the share to the parent..
	err = pcks.SendToParent(&share)
	if err != nil{
		return &bfv.Ciphertext{},err
	}


	//check if its the root then aggregate else wait on the parent.
	cipher := bfvCtx.NewCiphertext(pcks.Ciphertext.Degree())
	if pcks.IsRoot(){
		protocol.KeySwitch(share,&pcks.Ciphertext,cipher)
	}else{
		res := (<-pcks.ChannelCiphertext)
		cipher = &res.Ciphertext
	}

	//send the result to your child
	err = pcks.SendToChildren(cipher)
	if err != nil{
		return &bfv.Ciphertext{},err
	}

	return cipher,nil
}