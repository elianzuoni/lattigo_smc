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

	if e := p.RegisterChannels(&p.ChannelParams, &p.ChannelPublicKeyShares, &p.ChannelPublicKey); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}



func (ckgp *CollectiveKeyGenerationProtocol) CollectiveKeyGeneration() (ring.Poly, error) {

	params := <-ckgp.ChannelParams
	log.Lvl3("Started CKG with params ", params.Params)
	err := ckgp.SendToChildren(&Parameters{params.Params})
	// forwards the params to children, no effect if leaf
	if err != nil {
		return ring.Poly{}, fmt.Errorf("could not forward parameters to the ")
	}
	bfvCtx, err := bfv.NewBfvContextWithParam(&params.Params)
	if err != nil {
		return ring.Poly{}, fmt.Errorf("recieved invalid parameter set")
	}

	crsGen, _ := dbfv.NewCRPGenerator([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'}, bfvCtx.ContextQ())
	ckg := dbfv.NewCKG(bfvCtx.ContextQ(), crsGen.Clock())
	//get si
	sk, err := utils.GetSecretKey(bfvCtx)

	//sk := bfvCt
	if err != nil {
		return ring.Poly{}, fmt.Errorf("error when loading the secret key: %s", err)
	}
	//generate p0,i
	if ckg.GenShare(sk.Get()) != nil {
		return ring.Poly{}, fmt.Errorf("cannot generate share: %s", err)
	}

	partial := ckg.GetShare()
	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			child := <-ckgp.ChannelPublicKeyShares
			err = ckg.AggregateShares([]*ring.Poly{&child.PublicKeyShare.Poly})
			if err != nil {
				log.Printf("Error on share aggregations : %s ", err)
			}
		}
	}

	//send to parent
	err = ckgp.SendToParent(&PublicKeyShare{*partial})
	// has no effect for root node
	if err != nil {
		return ring.Poly{}, err
	}
	//propagate down the tree.
	var ckg_0 ring.Poly
	if ckgp.IsRoot() {
		ckg_0 = *partial // if node is root, the combined key is the final collective key
	} else {
		ckg_0 = (<-ckgp.ChannelPublicKey).Poly // else, receive it from parents
	}
	err = ckgp.SendToChildren(&PublicKey{ckg_0})
	// forward the collective key to children
	if err != nil {
		return ring.Poly{}, err
	}

	return ckg_0, nil
}


