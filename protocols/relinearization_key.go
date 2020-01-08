//Relinearization key protocol - used to generate a relinearization key that can be used to linearize ciphertexts after multiplication
// 1. allocate shares and generate share for round 1
// 2. Aggregate shares of round 1 from children
// 3. Send aggregated shares to parent - root has total aggregation sends to children
// 4. Get result of aggregations from parent - send to children
// 5. Generate shares for round 2
// 6. Aggregate shares of round 2 form children
// 7. Send result to parent - root has total aggregation sends to children
// 8. Get result of round 2 from parent
// 9. Same as 5-6-7-8 for round 3 shares
// 10. With shares of round 2 and 3 - generate the relinearization key.

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

const RelinearizationKeyProtocolName = "RelinearizationKeyProtocol"

func init() {
	_, _ = onet.GlobalProtocolRegister(RelinearizationKeyProtocolName, NewRelinearizationKey)
}

//Init initializes the variable for the protocol. Should be called before dispatch
func (rkp *RelinearizationKeyProtocol) Init(params bfv.Parameters, sk bfv.SecretKey, crp []*ring.Poly) error {
	rkp.Params = params
	rkp.Sk = sk
	rkp.Crp = CRP{crp}
	rkp.RelinProto = dbfv.NewEkgProtocol(&params)

	rkp.U = rkp.RelinProto.NewEphemeralKey(1.0 / 3.0)
	rkp.RoundOneShare, rkp.RoundTwoShare, rkp.RoundThreeShare = rkp.RelinProto.AllocateShares()
	rkp.RelinProto.GenShareRoundOne(rkp.U, sk.Get(), crp, rkp.RoundOneShare)

	rkp.EvaluationKey = bfv.NewRelinKey(&params, 1)
	return nil

}

//NewRelinearizationKey initializes a new protocol, registers the channels
func NewRelinearizationKey(n *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
	p := &RelinearizationKeyProtocol{
		TreeNodeInstance: n,
		Cond:             sync.NewCond(&sync.Mutex{}),
	}

	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelRoundOne, &p.ChannelRoundTwo, &p.ChannelRoundThree, &p.ChannelEvalKey); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

/**********ONET HANDLERS *****************/

//Start starts the protocol only at root
func (rlp *RelinearizationKeyProtocol) Start() error {
	log.Lvl3(rlp.ServerIdentity(), " : starting relin key protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (rlp *RelinearizationKeyProtocol) Dispatch() error {
	log.Lvl3(rlp.ServerIdentity(), " : Dispatching for relinearization key protocol! ")
	err := rlp.SendToChildren(&Start{})
	if err != nil {
		log.Error("Error when sending start up message : ", err)
		return err
	}
	//get the parameters..
	log.Lvl3(rlp.ServerIdentity(), " : starting relin key ")

	//aggregate the shares.
	if !rlp.IsLeaf() {
		for range rlp.Children() {
			h0 := (<-rlp.ChannelRoundOne).RKGShareRoundOne
			rlp.RelinProto.AggregateShareRoundOne(h0, rlp.RoundOneShare, rlp.RoundOneShare)
		}
	}

	//send to parent
	err = rlp.SendToParent(&rlp.RoundOneShare)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if !rlp.IsRoot() {
		rlp.RoundOneShare = (<-rlp.ChannelRoundOne).RKGShareRoundOne

	}
	_ = rlp.SendToChildren(&rlp.RoundOneShare)
	log.Lvl3(rlp.ServerIdentity().String(), ": round 1 share finished")

	//now we do round 2
	rlp.RelinProto.GenShareRoundTwo(rlp.RoundOneShare, rlp.Sk.Get(), rlp.Crp.A, rlp.RoundTwoShare)
	if !rlp.IsLeaf() {
		for range rlp.Children() {
			h0 := (<-rlp.ChannelRoundTwo).RKGShareRoundTwo
			rlp.RelinProto.AggregateShareRoundTwo(h0, rlp.RoundTwoShare, rlp.RoundTwoShare)
		}
	}

	//send to parent
	err = rlp.SendToParent(&rlp.RoundTwoShare)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if !rlp.IsRoot() {

		rlp.RoundTwoShare = (<-rlp.ChannelRoundTwo).RKGShareRoundTwo

	}

	_ = rlp.SendToChildren(&rlp.RoundTwoShare)
	log.Lvl3(rlp.ServerIdentity().String(), " : done with round 2 ")
	//now round 3....
	rlp.RelinProto.GenShareRoundThree(rlp.RoundTwoShare, rlp.U, rlp.Sk.Get(), rlp.RoundThreeShare)

	if !rlp.IsLeaf() {
		for range rlp.Children() {
			h0 := (<-rlp.ChannelRoundThree).RKGShareRoundThree
			rlp.RelinProto.AggregateShareRoundThree(h0, rlp.RoundThreeShare, rlp.RoundThreeShare)
		}
	}

	_ = rlp.SendToParent(&rlp.RoundThreeShare)
	//now we can generate key.
	log.Lvl3(rlp.ServerIdentity(), ": generating the relin key ! ")
	//since all parties should have r2 and r3 dont need to send it.
	if rlp.IsRoot() {
		rlp.RelinProto.GenRelinearizationKey(rlp.RoundTwoShare, rlp.RoundThreeShare, rlp.EvaluationKey)
	}

	rlp.Done()

	rlp.Cond.Broadcast()
	log.Lvl3(rlp.ServerIdentity(), " : exiting dispatch ")
	return nil
}

//Wait blocks until the protocol completes.
func (rlp *RelinearizationKeyProtocol) Wait() {
	rlp.Cond.L.Lock()
	rlp.Cond.Wait()
	rlp.Cond.L.Unlock()
}
