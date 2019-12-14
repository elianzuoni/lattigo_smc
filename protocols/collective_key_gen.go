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
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"sync"
)

//CollectiveKeyGenerationProtocolName name of protocol for onet
const CollectiveKeyGenerationProtocolName = "CollectiveKeyGeneration"

func init() {

	if _, err := onet.GlobalProtocolRegister(CollectiveKeyGenerationProtocolName, NewCollectiveKeyGeneration); err != nil {
		log.ErrFatal(err, "Could not register CollectiveKeyGeneration protocol : ")
	}

}

/****************ONET HANDLERS ******************/
//Start starts the protocol only at root
func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl2(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	log.Lvl2(ckgp.ServerIdentity(), " Dispatching ; is root = ", ckgp.IsRoot())

	//When running a simulation we need to send a wake up message to the children so all nodes can run!
	log.Lvl4("Sending wake up message")
	err := ckgp.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	PublicKey, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}
	ckgp.Pk = PublicKey

	//for the test - send all to root and in the test check that all keys are equals.
	if Test() {
		err = ckgp.SendTo(ckgp.Root(), &PublicKey)
		if err != nil {
			log.Lvl4("Error in key sending to root : ", err)
		}

	}

	log.Lvl2(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	ckgp.Cond.Broadcast()

	if Test() && !ckgp.IsRoot() {
		ckgp.Done()

	}
	return nil
}

func (ckgp *CollectiveKeyGenerationProtocol) Wait() {
	ckgp.Cond.L.Lock()
	ckgp.Cond.Wait()
	ckgp.Cond.L.Unlock()
}

/********PROTOCOL****************/
//NewCollectiveKeyGeneration is called when a new protocol is started. Will initialize the channels used to communicate between the nodes.
func NewCollectiveKeyGeneration(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("NewCollectiveKeyGen called")
	params := bfv.DefaultParams[0]
	p := &CollectiveKeyGenerationProtocol{
		TreeNodeInstance: n,
		//todo maybe register some channels here cf unlynx/protocols/key_switching - for feedback
		Params: *params,
		Sk:     *bfv.NewSecretKey(params),
		Cond:   sync.NewCond(&sync.Mutex{}),
	}

	if e := p.RegisterChannels(&p.ChannelPublicKeyShares, &p.ChannelPublicKey, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	if !AssignParametersBeforeStart {
		params := bfv.DefaultParams[0]
		p.Params = *params
		p.Sk = *bfv.NewKeyGenerator(params).NewSecretKey()

	}

	return p, nil
}

//CollectiveKeyGeneration runs the protocol. Returns the publickey and an error if there is any
func (ckgp *CollectiveKeyGenerationProtocol) CollectiveKeyGeneration() (bfv.PublicKey, error) {

	//Set up the parameters - context and the crp
	params := ckgp.Params

	//todo have a different seed at each generation.
	//Generate random ckg_1
	crsGen := dbfv.NewCRPGenerator(&params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	ckg1 := params.NewPolyQP()
	crsGen.Clock(ckg1)

	ckg := dbfv.NewCKGProtocol(&params)
	//get si
	sk := ckgp.Sk

	//generate p0,i
	partial := ckg.AllocateShares()
	ckg.GenShare(sk.Get(), ckg1, partial)
	log.Lvl3(ckgp.ServerIdentity(), " generated secret key - waiting for aggregation")

	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			child := <-ckgp.ChannelPublicKeyShares
			log.Lvl4(ckgp.ServerIdentity(), "Got from shared from child ")
			ckg.AggregateShares(child.CKGShare, partial, partial)

		}
	}

	//send to parent
	log.Lvl4(ckgp.ServerIdentity(), " sending my partial key : ", partial)
	err := ckgp.SendToParent(partial)

	if err != nil {
		return bfv.PublicKey{}, err
	}

	log.Lvl4(ckgp.ServerIdentity(), "Sent partial")

	pubkey := bfv.NewPublicKey(&params)
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

	//save the key in the protocol
	ckgp.Pk = *pubkey

	return *pubkey, nil
}
