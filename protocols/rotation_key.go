package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

const RotationProtocolName = "RotationKeyProtocol"

func init() {
	_, _ = onet.GlobalProtocolRegister(RotationProtocolName, NewRotationKey)
}

//Init initializes the variable for the protocol. Should be called before dispatch
func (rkp *RotationKeyProtocol) Init(params *bfv.Parameters, sk bfv.SecretKey, rottype bfv.Rotation, k uint64, crp []*ring.Poly, new bool, rotkey *bfv.RotationKeys) error {

	rkp.Params = *params
	rkp.Crp = crp

	rkp.RotationProtocol = dbfv.NewRotKGProtocol(params)
	rkp.RTShare = rkp.RotationProtocol.AllocateShare()
	//need rottype, k , sk and crp
	rkp.RotationProtocol.GenShare(rottype, k, sk.Get(), crp, &rkp.RTShare)
	if new {
		rkp.RotKey = *bfv.NewRotationKeys()

	} else {
		rkp.RotKey = *rotkey
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
