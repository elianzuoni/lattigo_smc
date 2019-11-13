package protocols

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
)

const CollectiveKeyGenerationProtocolName = "CollectiveKeyGeneration"

func init() {

	if _, err := onet.GlobalProtocolRegister(CollectiveKeyGenerationProtocolName, NewCollectiveKeyGeneration); err != nil {
		log.ErrFatal(err, "Could not register CollectiveKeyGeneration protocol : ")
	}

	//todo here could register messages if marshalling does not work .

}

func NewCollectiveKeyGeneration(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1("NewCollectiveKeyGen called")
	p := &CollectiveKeyGenerationProtocol{
		TreeNodeInstance: n,
		//todo maybe register some channels here cf unlynx/protocols/key_switching - for feedback
	}

	if e := p.RegisterChannels(&p.ChannelPublicKeyShares, &p.ChannelPublicKey, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

func (ckgp *CollectiveKeyGenerationProtocol) CollectiveKeyGeneration() (bfv.PublicKey, error) {

	//Set up the parameters - context and the crp
	bfvCtx, err := bfv.NewBfvContextWithParam(&ckgp.Params)
	if err != nil {
		return bfv.PublicKey{}, fmt.Errorf("recieved invalid parameter set")
	}
	//todo have a different seed at each generation.
	//todo ask what new crp is !
	crsGen, _ := dbfv.NewCRPGenerator([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'}, bfvCtx.ContextQ())
	ckg := dbfv.NewCKGProtocol(bfvCtx)
	//get si
	sk, err := utils.GetSecretKey(bfvCtx, ckgp.ServerIdentity().String())
	if err != nil {
		return bfv.PublicKey{}, fmt.Errorf("error when loading the secret key: %s", err)
	}

	b, err := sk.MarshalBinary()
	log.Lvl4(ckgp.ServerIdentity(), " my secret key : ", b)

	//generate p0,i
	partial := ckg.AllocateShares()
	ckg_1 := crsGen.Clock()
	ckg.GenShare(sk.Get(), ckg_1, partial)
	log.Lvl1(ckgp.ServerIdentity(), " generated secret key - waiting for aggregation")

	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			log.Lvl4(ckgp.ServerIdentity(), "waiting..", i)
			child := <-ckgp.ChannelPublicKeyShares
			log.Lvl4("Got from child : ", child.CKGShare)
			ckg.AggregateShares(child.CKGShare, partial, partial)

		}
	}

	//send to parent
	log.Lvl4(ckgp.ServerIdentity(), " sending my partial key : ", partial)
	err = ckgp.SendToParent(partial)

	if err != nil {
		return bfv.PublicKey{}, err
	}

	log.Lvl4(ckgp.ServerIdentity(), "Sent partial")

	pubkey := bfvCtx.NewPublicKey()
	if ckgp.IsRoot() {
		ckg.GenPublicKey(partial, ckg_1, pubkey) // if node is root, the combined key is the final collective key
	} else {
		coeffs := (<-ckgp.ChannelPublicKey)
		pubkey.Set(coeffs.Get())
	}

	//send it to the children
	if err = ckgp.SendToChildren(pubkey); err != nil {
		return bfv.PublicKey{}, err
	}

	log.Lvl4(ckgp.ServerIdentity(), "sent PublicKey : ", pubkey)

	//save the key in the a public file.
	err = utils.SavePublicKey(pubkey, bfvCtx, ckgp.ServerIdentity().String())
	if err != nil {
		return *pubkey, err
	}

	return *pubkey, nil
}
