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
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"sync"
)

func init() {
	_, _ = onet.GlobalProtocolRegister("RelinearizationKeyProtocol", NewRelinearizationKey)
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
	res, err := rlp.RelinearizationKey()
	if err != nil {
		log.Error("Error in RLProtocol :  ", err)
		return err
	}

	if Test() {
		_ = rlp.SendTo(rlp.Root(), &res)
	}

	if !rlp.IsRoot() && Test() {
		rlp.Done()
	}
	rlp.Cond.Broadcast()
	log.Lvl3(rlp.ServerIdentity(), " : exiting dispatch ")
	return nil
}

func (rlp *RelinearizationKeyProtocol) Wait() {
	rlp.Cond.L.Lock()
	rlp.Cond.Wait()
	rlp.Cond.L.Unlock()
}

//RelinearizationKey runs the relinearization protocol returns the evaluation key ( relinearization key ) and error if there is any.
func (rlp *RelinearizationKeyProtocol) RelinearizationKey() (bfv.EvaluationKey, error) {
	//get the parameters..
	log.Lvl3(rlp.ServerIdentity(), " : starting relin key ")

	//can start protocol now.
	params := (rlp.Params)

	rkg := dbfv.NewEkgProtocol(&params)
	u := rkg.NewEphemeralKey(1.0 / 3.0)
	sk := rlp.Sk

	//Allocation
	r1, r2, r3 := rkg.AllocateShares()
	//Round 1
	rkg.GenShareRoundOne(u, sk.Get(), rlp.Crp.A, r1)
	//aggregate the shares.
	if !rlp.IsLeaf() {
		for range rlp.Children() {
			h0 := (<-rlp.ChannelRoundOne).RKGShareRoundOne
			rkg.AggregateShareRoundOne(h0, r1, r1)
		}
	}

	//send to parent
	err := rlp.SendToParent(&r1)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if !rlp.IsRoot() {
		r1 = (<-rlp.ChannelRoundOne).RKGShareRoundOne

	}
	_ = rlp.SendToChildren(&r1)
	log.Lvl3(rlp.ServerIdentity().String(), ": round 1 share finished")

	//now we do round 2
	rkg.GenShareRoundTwo(r1, sk.Get(), rlp.Crp.A, r2)
	if !rlp.IsLeaf() {
		for range rlp.Children() {
			h0 := (<-rlp.ChannelRoundTwo).RKGShareRoundTwo
			rkg.AggregateShareRoundTwo(h0, r2, r2)
		}
	}

	//send to parent
	err = rlp.SendToParent(&r2)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if !rlp.IsRoot() {

		r2 = (<-rlp.ChannelRoundTwo).RKGShareRoundTwo

	}

	_ = rlp.SendToChildren(&r2)
	log.Lvl3(rlp.ServerIdentity().String(), " : done with round 2 ")
	//now round 3....
	rkg.GenShareRoundThree(r2, u, sk.Get(), r3)

	if !rlp.IsLeaf() {
		for range rlp.Children() {
			h0 := (<-rlp.ChannelRoundThree).RKGShareRoundThree
			rkg.AggregateShareRoundThree(h0, r3, r3)
		}
	}

	//send to parent
	err = rlp.SendToParent(&r3)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if !rlp.IsRoot() {
		r3 = (<-rlp.ChannelRoundThree).RKGShareRoundThree

	}
	_ = rlp.SendToChildren(&r3)

	//now we can generate key.
	log.Lvl3(rlp.ServerIdentity(), ": generating the relin key ! ")
	//since all parties should have r2 and r3 dont need to send it.
	evalKey := bfv.NewRelinKey(&params, 1) //todo check if ok
	rkg.GenRelinearizationKey(r2, r3, evalKey)

	return *evalKey, nil
}
