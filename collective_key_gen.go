package main

import (
	"errors"
	"fmt"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"

	"github.com/lca1/lattigo/bfv"
	"github.com/lca1/lattigo/dbfv"
	"github.com/lca1/lattigo/ring"
)


func init() {
	onet.GlobalProtocolRegister("FVCollectiveKeyGeneration", NewCollectiveKeyGeneration)
}

type CollectiveKeyGenerationProtocol struct {
	*onet.TreeNodeInstance

	Params bfv.Parameters

	ChannelParams          chan StructParameters
	ChannelPublicKeyShares chan StructPublicKeyShare
	ChannelPublicKey       chan StructPublicKey
}

type Parameters struct {
	Params bfv.Parameters
}

type PublicKeyShare struct {
	ring.Poly
}

type PublicKey struct {
	CKG_0 ring.Poly
}

type StructParameters struct {
	*onet.TreeNode
	Parameters
}

type StructPublicKeyShare struct {
	*onet.TreeNode
	PublicKeyShare
}

type StructPublicKey struct {
	*onet.TreeNode
	PublicKey
}

func NewCollectiveKeyGeneration(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectiveKeyGenerationProtocol{
		TreeNodeInstance:       n,
	}

	if e := p.RegisterChannels(&p.ChannelParams, &p.ChannelPublicKeyShares, &p.ChannelPublicKey); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl1(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	ckgp.ChannelParams <- StructParameters{nil, Parameters{ckgp.Params}}
	return nil
}

func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	params := <-ckgp.ChannelParams
	log.Printf("Started CKG with params %+v", params.Params)
	err := ckgp.SendToChildren(&Parameters{params.Params}) // forwards the params to children, no effect if leaf
	if err != nil {
		return fmt.Errorf("could not forward parameters to the ")
	}

	bfvCtx, err := bfv.NewBfvContextWithParam(params.Params.N, params.Params.T, params.Params.Qi, params.Params.Pi, params.Params.Sigma)
	if err != nil {
		return fmt.Errorf("recieved invalid parameter set")
	}

	crsGen, _ := dbfv.NewCRPGenerator([]byte{'l','a', 't', 't', 'i', 'g', 'o'}, bfvCtx.GetContextQ())
	ckg := dbfv.NewCKG(bfvCtx.GetContextQ(), crsGen.Clock())

	sk, err := GetSecretKey(bfvCtx)
	if err != nil {
		return fmt.Errorf("error when loading the secret key: %s", err)
	}

	if ckg.GenShare(sk.Get()) != nil {
		return fmt.Errorf("cannot generate share: %s", err)
	}

	partial := ckg.GetShare()
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			child := (<-ckgp.ChannelPublicKeyShares)
			_ = ckg.AggregateShares([]*ring.Poly{&child.PublicKeyShare.Poly})
		}
	}


	err = ckgp.SendToParent(&PublicKeyShare{*partial}) // has no effect for root node
	if err != nil {
		return err
	}

	var ckg_0 ring.Poly
	if ckgp.IsRoot() {
		ckg_0 = *partial // if node is root, the combined key is the final collective key
	} else {
		ckg_0 = (<-ckgp.ChannelPublicKey).CKG_0 // else, receive it from parents
	}
	err = ckgp.SendToChildren(&PublicKey{ckg_0}) // forward the collective key to children
	if err != nil {
		return err
	}

	log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	return nil
}
