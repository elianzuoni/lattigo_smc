package protocols

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

//CollectiveKeyGenerationProtocolName name of protocol for onet
const CollectiveRefreshName = "CollectiveRefreshKey"

func init() {
	fmt.Println("RefProto: init")

	if _, err := onet.GlobalProtocolRegister(CollectiveRefreshName, NewCollectiveRefresh); err != nil {
		log.ErrFatal(err, "Could not register CollectiveKeyGeneration protocol : ")
	}

	_ = network.RegisterMessage(&StructStart{})
	_ = network.RegisterMessage(&StructRShare{})

}

//Init initializes the variables for the protocol. Should be called before the dispatch
func (rkp *RefreshProtocol) Init(params bfv.Parameters, sk *bfv.SecretKey, ciphertext bfv.Ciphertext, crs ring.Poly) error {
	rkp.Sk = *sk
	rkp.Ciphertext = ciphertext
	rkp.FinalCiphertext = *bfv.NewCiphertext(&params, ciphertext.Degree())
	rkp.CRS = crs
	rkp.Params = params

	//Parameters for refresh
	rkp.RefreshProto = dbfv.NewRefreshProtocol(&params)
	rkp.RShare = rkp.RefreshProto.AllocateShares()
	rkp.RefreshProto.GenShares(sk.Get(), &rkp.Ciphertext, &rkp.CRS, rkp.RShare)

	return nil
}

//NewCollectiveRefresh is called when a new protocol is started. Will initialize the channels used to communicate between the nodes.
func NewCollectiveRefresh(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("NewCollectiveRefresh called")

	p := &RefreshProtocol{
		TreeNodeInstance: n,
	}

	p.done.Lock()

	if e := p.RegisterChannels(&p.ChannelRShare, &p.ChannelStart); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//Start starts the protocol only at root
func (rkp *RefreshProtocol) Start() error {
	log.Lvl2(rkp.ServerIdentity(), "Started refresh key protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (rkp *RefreshProtocol) Dispatch() error {

	log.Lvl2(rkp.ServerIdentity(), " Dispatching ; is root = ", rkp.IsRoot())

	//When running a simulation we need to send a wake up message to the children so all nodes can run!
	log.Lvl4("Sending wake up message")
	err := rkp.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	//Set up the parameters - context and the crp

	//if parent get share from child and aggregate
	if !rkp.IsLeaf() {
		for i := 0; i < len(rkp.Children()); i++ {
			child := <-rkp.ChannelRShare
			rkp.RefreshProto.Aggregate(child.RefreshShare, rkp.RShare, rkp.RShare)

		}
	}

	//send to parent
	err = rkp.SendToParent(&rkp.RShare)

	if err != nil {
		return err
	}

	log.Lvl4(rkp.ServerIdentity(), "Sent partial")

	if rkp.IsRoot() {
		rkp.RefreshProto.Finalize(&rkp.Ciphertext, &rkp.CRS, rkp.RShare, &rkp.FinalCiphertext)
	}

	log.Lvl2(rkp.ServerIdentity(), "Completed Collective Public Refresh protocol ")

	rkp.done.Unlock()

	rkp.Done()
	return nil
}

/*********************** Not onet handlers ************************/

// By calling this method, the root can wait for termination of the protocol.
// It is safe to call multiple times.
func (p *RefreshProtocol) WaitDone() {
	log.Lvl3("Waiting for protocol to end")
	p.done.Lock()
	// Unlock again so that subsequent calls to WaitDone do not block forever
	p.done.Unlock()
}
