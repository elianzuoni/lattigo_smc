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
	"github.com/ldsec/lattigo/ring"
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

func (ckgp *CollectiveKeyGenerationProtocol) Init(params *bfv.Parameters, sk *bfv.SecretKey, crp *ring.Poly) error {
	defer func() { go func() { ckgp.Initialized <- true; log.Lvl1(ckgp.ServerIdentity(), "Init ok") }() }()
	//Set up the parameters - context and the crp
	ckgp.Params = params.Copy()
	ckgp.Sk = sk
	ckgp.Pk = bfv.NewPublicKey(ckgp.Params)
	ckgp.CKGProtocol = dbfv.NewCKGProtocol(ckgp.Params)

	//Copies ckg_1
	ckgp.CKG1 = ckgp.Params.NewPolyQP()
	ckgp.CKG1.Copy(crp)

	//generate p0,i
	ckgp.CKGShare = ckgp.AllocateShares()
	ckgp.GenShare(sk.Get(), ckgp.CKG1, ckgp.CKGShare)
	log.Lvl1(ckgp.ServerIdentity(), "PIIIIIING")
	return nil
}

/****************ONET HANDLERS ******************/

//Start starts the protocol only at root
func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl2(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {
	<-ckgp.Initialized

	log.Lvl3(ckgp.ServerIdentity(), " Dispatching ; is root = ", ckgp.IsRoot())
	if &ckgp.Sk == nil {
		return nil
	}

	//When running a simulation we need to send a wake up message to the children so all nodes can run!
	log.Lvl3("Sending wake up message")
	tosend := Start{
		//ParamsIdx: utils.GetParametersIdx(ckgp.Params),
		//Poly:      ckgp.CKG1,
	}
	err := ckgp.SendToChildren(&tosend)
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			child := <-ckgp.ChannelPublicKeyShares
			log.Lvl3(ckgp.ServerIdentity(), "Got share from child ")
			ckgp.AggregateShares(child.CKGShare, ckgp.CKGShare, ckgp.CKGShare)

		}
	}

	//send to parent
	err = ckgp.SendToParent(ckgp.CKGShare)
	if err != nil {
		return err
	}
	log.Lvl3(ckgp.ServerIdentity(), "sent collective key share to parent")

	if ckgp.IsRoot() {
		ckgp.GenPublicKey(ckgp.CKGShare, ckgp.CKG1, ckgp.Pk)
	}

	log.Lvl2(ckgp.ServerIdentity(), "completed Collective Public Key Generation protocol ")
	ckgp.Cond.Broadcast()

	ckgp.Done()

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
	log.Lvl3("NewCollectiveKeyGen called")

	p := &CollectiveKeyGenerationProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
		Initialized:      make(chan bool),
	}

	if e := p.RegisterChannels(&p.ChannelPublicKeyShares, &p.ChannelPublicKey, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}
