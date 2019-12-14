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
const CollectiveRefreshKeyGeneration = "CollectiveRefreshKey"

func init() {

	if _, err := onet.GlobalProtocolRegister(CollectiveRefreshKeyGeneration, NewCollectiveRefresh); err != nil {
		log.ErrFatal(err, "Could not register CollectiveKeyGeneration protocol : ")
	}

}

//NewCollectiveKeyGeneration is called when a new protocol is started. Will initialize the channels used to communicate between the nodes.
func NewCollectiveRefresh(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("NewCollectiveRefresh called")

	p := &RefreshKeyProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
	}

	if e := p.RegisterChannels(&p.ChannelCiphertext, &p.ChannelRShare, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	if !AssignParametersBeforeStart {
		params := bfv.DefaultParams[0]
		p.Params = *params
		p.Sk = *bfv.NewKeyGenerator(params).NewSecretKey()

	}

	return p, nil
}

/****************ONET HANDLERS ******************/
//Start starts the protocol only at root
func (rkp *RefreshKeyProtocol) Start() error {
	log.Lvl2(rkp.ServerIdentity(), "Started refresh key protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (rkp *RefreshKeyProtocol) Dispatch() error {

	log.Lvl2(rkp.ServerIdentity(), " Dispatching ; is root = ", rkp.IsRoot())
	defer rkp.Cond.Broadcast()

	//When running a simulation we need to send a wake up message to the children so all nodes can run!
	log.Lvl4("Sending wake up message")
	err := rkp.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	ciphertext, e := rkp.RefreshKeyProtocol()
	if e != nil {
		return e
	}

	//for the test - send all to root and in the test check that all keys are equals.
	if Test() {
		err = rkp.SendTo(rkp.Root(), &ciphertext)
		if err != nil {
			log.Lvl4("Error in key sending to root : ", err)
		}

	}

	log.Lvl2(rkp.ServerIdentity(), "Completed Collective Public Refresh protocol ")

	if Test() && !rkp.IsRoot() {
		log.Lvl1("Done")
		rkp.Done()

	}
	return nil
}

func (rkp *RefreshKeyProtocol) Wait() {
	rkp.Cond.L.Lock()
	rkp.Cond.Wait()
	rkp.Cond.L.Unlock()
}

/********PROTOCOL****************/

//CollectiveKeyGeneration runs the protocol. Returns the publickey and an error if there is any
func (rkp *RefreshKeyProtocol) RefreshKeyProtocol() (bfv.Ciphertext, error) {

	//Set up the parameters - context and the crp
	params := rkp.Params
	//for debug...
	data, _ := rkp.Ciphertext.MarshalBinary()
	log.Lvl1("Original cipher :", data[0:25])
	data, _ = rkp.CRS.MarshalBinary()
	log.Lvl1("CRP :", data[0:25])
	data, _ = rkp.Sk.MarshalBinary()
	log.Lvl1(rkp.ServerIdentity(), " : sk = ", data[0:25])
	refproto := dbfv.NewRefreshProtocol(&params)
	//get si
	sk := rkp.Sk

	//generate share0
	partial := refproto.AllocateShares()
	refproto.GenShares(sk.Get(), &rkp.Ciphertext, &rkp.CRS, partial)
	log.Lvl3(rkp.ServerIdentity(), " generated share - waiting for aggregation")

	//if parent get share from child and aggregate
	if !rkp.IsLeaf() {
		for i := 0; i < len(rkp.Children()); i++ {
			child := <-rkp.ChannelRShare
			d, _ := child.MarshalBinary()
			log.Lvl1(rkp.ServerIdentity(), "Got from share from child : ", d[0:25])
			refproto.Aggregate(child.RefreshShare, partial, partial)

		}
	}

	//send to parent
	data, _ = partial.MarshalBinary()
	log.Lvl1(rkp.ServerIdentity(), " sending my partial key  :  ", data[0:25])
	err := rkp.SendToParent(&partial)

	if err != nil {
		return bfv.Ciphertext{}, err
	}

	log.Lvl4(rkp.ServerIdentity(), "Sent partial")

	if !rkp.IsRoot() {
		log.Lvl1("getting final cipher from parent.:")
		finalShare := (<-rkp.ChannelRShare).RefreshShare
		partial = finalShare
	}

	//send it to the children
	if err = rkp.SendToChildren(&partial); err != nil {
		return bfv.Ciphertext{}, err
	}

	resultingCipher := bfv.NewCiphertextRandom(&params, rkp.Ciphertext.Degree())
	refproto.Finalize(&rkp.Ciphertext, &rkp.CRS, partial, resultingCipher)

	log.Lvl4(rkp.ServerIdentity(), "sent resulting cipher ")

	//save the key in the protocol
	rkp.FinalCiphertext = *resultingCipher

	return *resultingCipher, nil
}
