package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
)

func NewRelinearizationKey(n *onet.TreeNodeInstance) (instance onet.ProtocolInstance, e error) {
	p := &RelinearizationKeyProtocol{
		TreeNodeInstance: n,
	}

	if e := p.RegisterChannels(&p.ChannelStart, &p.ChannelRoundOne, &p.ChannelRoundTwo, &p.ChannelRoundThree, &p.ChannelEvalKey); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

const BitDecomp = 64

func (rlp *RelinearizationKeyProtocol) RelinearizationKey() (bfv.EvaluationKey, error) {
	//get the parameters..
	log.Lvl1(rlp.ServerIdentity(), " : starting relin key ")

	//can start protocol now.
	bfvCtx, err := bfv.NewBfvContextWithParam(&rlp.Params)
	if err != nil {
		log.Error("Could not start bfv context : ", err)
		return *new(bfv.EvaluationKey), err
	}

	rkg := dbfv.NewEkgProtocol(bfvCtx, BitDecomp)
	u, _ := rkg.NewEphemeralKey(1 / 3.0)
	sk, err := utils.GetSecretKey(bfvCtx, rlp.Sk.SecretKey+rlp.ServerIdentity().String())
	if err != nil {
		log.Error("Could not generate secret key : ", err)
		return *new(bfv.EvaluationKey), err
	}
	//Allocation
	r1, r2, r3 := rkg.AllocateShares()
	//Round 1
	rkg.GenShareRoundOne(u, sk.Get(), rlp.Crp.A, r1)
	//aggregate the shares.
	if !rlp.IsLeaf() {
		for _ = range rlp.Children() {
			h0 := (<-rlp.ChannelRoundOne).RKGShareRoundOne
			rkg.AggregateShareRoundOne(h0, r1, r1)
		}
	}

	//send to parent
	err = rlp.SendToParent(&r1)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if rlp.IsRoot() {
		_ = rlp.SendToChildren(&r1)
	} else {
		r1 = (<-rlp.ChannelRoundOne).RKGShareRoundOne

	}
	log.Lvl3(rlp.ServerIdentity().String(), ": round 1 share finished")

	//now we do round 2
	rkg.GenShareRoundTwo(r1, sk.Get(), rlp.Crp.A, r2)
	if !rlp.IsLeaf() {
		for _ = range rlp.Children() {
			h0 := (<-rlp.ChannelRoundTwo).RKGShareRoundTwo
			rkg.AggregateShareRoundTwo(h0, r2, r2)
		}
	}

	//send to parent
	err = rlp.SendToParent(&r2)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if rlp.IsRoot() {
		_ = rlp.SendToChildren(&r2)
	} else {
		r2 = (<-rlp.ChannelRoundTwo).RKGShareRoundTwo

	}
	log.Lvl3(rlp.ServerIdentity().String(), " : done with round 2 ")
	//now round 3....
	rkg.GenShareRoundThree(r2, u, sk.Get(), r3)

	if !rlp.IsLeaf() {
		for _ = range rlp.Children() {
			h0 := (<-rlp.ChannelRoundThree).RKGShareRoundThree
			rkg.AggregateShareRoundThree(h0, r3, r3)
		}
	}

	//send to parent
	err = rlp.SendToParent(&r3)
	if err != nil {
		log.Error("Could not send round one share to parent : ", err)
	}

	if rlp.IsRoot() {
		_ = rlp.SendToChildren(&r3)
	} else {
		r3 = (<-rlp.ChannelRoundThree).RKGShareRoundThree

	}

	//now we can generate key.
	log.Lvl3(rlp.ServerIdentity(), ": generating the relin key ! ")
	//since all parties should have r2 and r3 dont need to send it.
	evalKey := rkg.AllocateEvaluationKey(*bfvCtx)
	rkg.GenRelinearizationKey(r2, r3, evalKey)

	return *evalKey, nil
}
