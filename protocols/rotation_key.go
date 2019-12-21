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

const RotationProtocolName = "RotationKeyProtocol"

func init() {
	_, _ = onet.GlobalProtocolRegister(RotationProtocolName, NewRotationKey)
}

func (rkp *RotationKeyProtocol) Init(params *bfv.Parameters, sk bfv.SecretKey, rottype bfv.Rotation, k uint64, crp []*ring.Poly) error {
	rkp.Params = *params
	rkp.Crp = crp

	rkp.RotationProtocol = dbfv.NewRotKGProtocol(params)
	rkp.RTShare = rkp.RotationProtocol.AllocateShare()
	//need rottype, k , sk and crp
	rkp.RotationProtocol.GenShare(rottype, k, sk.Get(), crp, &rkp.RTShare)
	rkp.RotKey = *bfv.NewRotationKeys()

	return nil
}

func NewRotationKey(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	//prepare the protocol
	p := &RotationKeyProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
	}
	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelRTShare); e != nil {
		return nil, errors.New("Could not register channel : " + e.Error())
	}

	return p, nil
}

func (rkp *RotationKeyProtocol) Start() error {
	log.Lvl3("Starting new rotation key protocol ! ")
	return nil
}

func (rkp *RotationKeyProtocol) Dispatch() error {
	err := rkp.SendToChildren(&Start{})
	if err != nil {
		log.Error("Could not send start message : ", err)
		return err
	}

	log.Lvl1(rkp.ServerIdentity(), "Starting rotation key protocol")
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

	log.Lvl1("Rotation protocol done. ")

	rkp.Done()
	rkp.Cond.Broadcast()
	return nil

}

func (rkp *RotationKeyProtocol) Wait() {
	rkp.Cond.L.Lock()
	rkp.Cond.Wait()
	rkp.Cond.L.Unlock()
}
