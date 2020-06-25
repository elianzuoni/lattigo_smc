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
	"sync"
)

/************************************** Structures **************************************/

//RotationKeyProtocol handler for onet for the rotation key protocol
type RotationKeyProtocol struct {
	*onet.TreeNodeInstance

	Params           bfv.Parameters
	RotationProtocol *dbfv.RTGProtocol
	RTShare          dbfv.RTGShare
	RotKey           bfv.RotationKeys

	Crp []*ring.Poly

	ChannelRTShare chan StructRTGShare
	ChannelStart   chan StructStart

	done sync.Mutex
}

//StructRTGShare handler for onet
type StructRTGShare struct {
	*onet.TreeNode
	dbfv.RTGShare
}

/************************************** Methods **************************************/

const RotationProtocolName = "RotationKeyProtocol"

func init() {
	fmt.Println("RKG: init")

	_, _ = onet.GlobalProtocolRegister(RotationProtocolName, NewRotationKey)

	_ = network.RegisterMessage(Start{})
	_ = network.RegisterMessage(dbfv.RTGShare{})
}

//Init initializes the variable for the protocol. Should be called before dispatch
// It augments the provided rotation key: if nil, it instantiates it
func (rkp *RotationKeyProtocol) Init(params *bfv.Parameters, sk bfv.SecretKey, rotKey *bfv.RotationKeys,
	rotIdx bfv.Rotation, k uint64, crp []*ring.Poly) error {
	rkp.Params = *params
	rkp.Crp = crp

	rkp.RotationProtocol = dbfv.NewRotKGProtocol(params)
	rkp.RTShare = rkp.RotationProtocol.AllocateShare()
	//need rotIdx, k , sk and crp
	rkp.RotationProtocol.GenShare(rotIdx, k, sk.Get(), crp, &rkp.RTShare)
	if rotKey == nil {
		rkp.RotKey = *bfv.NewRotationKeys()
	} else {
		rkp.RotKey = *rotKey
	}

	return nil
}

//NewRotationKey creates a new rotation key and register the channels
func NewRotationKey(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	//prepare the protocol
	p := &RotationKeyProtocol{
		TreeNodeInstance: n,
	}

	p.done.Lock()

	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelRTShare); e != nil {
		return nil, errors.New("Could not register channel : " + e.Error())
	}

	return p, nil
}

//Start starts the protocol at the root
func (rkp *RotationKeyProtocol) Start() error {
	log.Lvl3("Starting new rotation key protocol ! ")
	return nil
}

//Dispatch runs the protocol
func (rkp *RotationKeyProtocol) Dispatch() error {
	err := rkp.SendToChildren(&Start{})
	if err != nil {
		log.Error("Could not send start message : ", err)
		return err
	}

	log.Lvl2(rkp.ServerIdentity(), "Starting rotation key protocol")
	if !rkp.IsLeaf() {
		for range rkp.Children() {
			share := (<-rkp.ChannelRTShare).RTGShare
			rkp.RotationProtocol.Aggregate(rkp.RTShare, share, rkp.RTShare)
		}
	}

	//send share to parent
	err = rkp.SendToParent(&rkp.RTShare)
	if err != nil {
		log.Error("Could not send rotation share to parent : ", err)
		return err
	}

	if rkp.IsRoot() {
		//root finalizes the protocol
		rkp.RotationProtocol.Finalize(rkp.RTShare, rkp.Crp, &rkp.RotKey)
	}

	log.Lvl2("Rotation protocol done. ")

	rkp.done.Unlock()

	rkp.Done()
	return nil

}

/*********************** Not onet handlers ************************/

// By calling this method, the root can wait for termination of the protocol.
// It is safe to call multiple times.
func (p *RotationKeyProtocol) WaitDone() {
	log.Lvl3("Waiting for protocol to end")
	p.done.Lock()
	// Unlock again so that subsequent calls to WaitDone do not block forever
	p.done.Unlock()
}
