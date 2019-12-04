// Collective key generation : the nodes collaborate to create a public key given their secret key shard.
// This key should then be used to encrypt the plain texts
// The protocol has the following steps :
// 0. Set-up : generate ( or load ) secret key, generate a random p1
// 1. Generate their partial key share
// 2. Aggregate the partial key share from the children
// 3. Send the result of aggregation to the parent ( note the leaf will just send the partial key share and the root nothing )
// 4. The root generates the public key and sends it to its children
// 5. Get the public key from the parents and forward to the children

package protocols

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"sync"
)

//CollectiveKeyGenerationProtocolName name of protocol for onet
const CollectiveKeyGenerationProtocolName = "CollectiveKeyGeneration"

func init() {

	if _, err := onet.GlobalProtocolRegister(CollectiveKeyGenerationProtocolName, NewCollectiveKeyGeneration); err != nil {
		log.ErrFatal(err, "Could not register CollectiveKeyGeneration protocol : ")
	}

	//todo here could register messages if marshalling does not work .

}

//NewCollectiveKeyGeneration is called when a new protocol is started. Will initialize the channels used to communicate between the nodes.
func NewCollectiveKeyGeneration(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1("NewCollectiveKeyGen called")
	p := &CollectiveKeyGenerationProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
		//todo maybe register some channels here cf unlynx/protocols/key_switching - for feedback
	}

	if e := p.RegisterChannels(&p.ChannelPublicKeyShares, &p.ChannelPublicKey, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//CollectiveKeyGeneration runs the protocol. Returns the publickey and an error if there is any
func (ckgp *CollectiveKeyGenerationProtocol) CollectiveKeyGeneration() (bfv.PublicKey, error) {

	//Set up the parameters - context and the crp
	bfvCtx := bfv.NewBfvContextWithParam(&ckgp.Params)

	//todo have a different seed at each generation.
	//todo ask what new crp is !
	//Generate random ckg_1
	crsGen := ring.NewCRPGenerator([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'}, bfvCtx.ContextKeys())
	ckg1 := crsGen.Clock()

	ckg := dbfv.NewCKGProtocol(bfvCtx)
	//get si
	sk, err := utils.GetSecretKey(bfvCtx, ckgp.ServerIdentity().String())
	if err != nil {
		return bfv.PublicKey{}, fmt.Errorf("error when loading the secret key: %s", err)
	}

	//generate p0,i
	partial := ckg.AllocateShares()
	ckg.GenShare(sk.Get(), ckg1, partial)
	log.Lvl1(ckgp.ServerIdentity(), " generated secret key - waiting for aggregation")

	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			log.Lvl4(ckgp.ServerIdentity(), "waiting..", i)
			child := <-ckgp.ChannelPublicKeyShares
			log.Lvl1(ckgp.ServerIdentity(), "Got from shared from child ")
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
		ckg.GenPublicKey(partial, ckg1, pubkey) // if node is root, the combined key is the final collective key
	} else {
		coeffs := <-ckgp.ChannelPublicKey
		pubkey.Set(coeffs.Get())
	}

	//send it to the children
	if err = ckgp.SendToChildren(pubkey); err != nil {
		return bfv.PublicKey{}, err
	}

	log.Lvl4(ckgp.ServerIdentity(), "sent PublicKey : ", pubkey)

	//save the key in the a public file.
	err = utils.SavePublicKey(pubkey, ckgp.ServerIdentity().String())
	if err != nil {
		return *pubkey, err
	}

	return *pubkey, nil
}
