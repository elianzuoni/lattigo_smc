package protocols

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
)





func NewCollectiveKeyGeneration(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectiveKeyGenerationProtocol{
		TreeNodeInstance:       n,
	}

	if e := p.RegisterChannels(&p.ChannelParams,  &p.ChannelPublicKeyShares,&p.ChannelPublicKey); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}



func (ckgp *CollectiveKeyGenerationProtocol) CollectiveKeyGeneration() (bfv.PublicKey, error) {

	params := <-ckgp.ChannelParams
	log.Lvl3("Started CKG with params ", params.Params)
	err := ckgp.SendToChildren(&params.Params)
	// forwards the params to children, no effect if leaf


	if err != nil {
		return bfv.PublicKey{}, fmt.Errorf("could not forward parameters to the ")
	}



	bfvCtx, err := bfv.NewBfvContextWithParam(&params.Params)
	if err != nil {
		return bfv.PublicKey{}, fmt.Errorf("recieved invalid parameter set")
	}



	crsGen, _ := dbfv.NewCRPGenerator([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'}, bfvCtx.ContextQ())
	ckg := dbfv.NewCKGProtocol(bfvCtx)
	//get si
	sk, err := utils.GetSecretKey(bfvCtx,ckgp.ServerIdentity().String())
	b , err := sk.MarshalBinary(bfvCtx)
	log.Lvl4(ckgp.ServerIdentity()," my secret key : " , b)
	if err != nil {
		return bfv.PublicKey{}, fmt.Errorf("error when loading the secret key: %s", err)
	}


	//generate p0,i
	partial := ckg.AllocateShares()
	ckg_1 := crsGen.Clock()
	ckg.GenShare(sk.Get(),ckg_1,partial)



	log.Lvl4(ckgp.ServerIdentity(), "Hello")
	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			log.Lvl4(ckgp.ServerIdentity(),"waiting..",i)
			child := <-ckgp.ChannelPublicKeyShares
			log.Lvl4("Got from child : ", child.Poly)
			ckg.AggregateShares(&child.Poly,partial,partial)

		}
	}



	//send to parent
	log.Lvl4(ckgp.ServerIdentity(), "Goodbye : " ,partial)
	sending := &CollectiveKeyShare{ring.Poly{partial.Coeffs}}

	// has no effect for root node
	err = ckgp.SendToParent(sending)

	log.Lvl4(ckgp.ServerIdentity(), "Sending : " , sending)

	if err != nil {
		return bfv.PublicKey{}, err
	}
	log.Lvl4(ckgp.ServerIdentity(), "Sent partial")


	var ckg_0 ring.Poly

	if ckgp.IsRoot()  {
		ckg_0 = ring.Poly{partial.Coeffs}
	}else{
		log.Lvl4("Fetching ckg0")
		ckg_0 = (<-ckgp.ChannelPublicKey).Poly // else, receive it from parents
		log.Lvl4("got : " , ckg_0)

	}

	err = ckgp.SendToChildren(&ckg_0)

	if err != nil{
		return bfv.PublicKey{},nil
	}
	//generate the key
	pubkey := bfvCtx.NewPublicKey()
	partial.Coeffs = ckg_0.Coeffs
	ckg.GenPublicKey(partial,ckg_1,pubkey) // if node is root, the combined key is the final collective key
	//send the ckg_0 to children


	log.Lvl4(ckgp.ServerIdentity(), "sent ckgo : " , pubkey)
	// forward the collective key to children
	//if err != nil {
	//	return bfv.PublicKey{}, err
	//}

	log.Lvl4(ckgp.ServerIdentity(), "Ugh")
	//save the key in the a public file.
	err = utils.SavePublicKey(pubkey,bfvCtx,ckgp.ServerIdentity().String())
	if err != nil{
		return *pubkey, err
	}
	return *pubkey, nil
}


