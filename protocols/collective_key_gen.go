package protocols

import (
	"errors"
	"fmt"
	"github.com/lca1/lattigo/bfv"
	"github.com/lca1/lattigo/dbfv"
	"github.com/lca1/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
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
	//Message string
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

//type StructPrivateKey struct{
//	//Might need to add more so declare it as struct
//	bfv.SecretKey
//}

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
	log.Printf("Parameters sent to children")
	if err != nil {
		return fmt.Errorf("could not forward parameters to the ")
	}

	bfvCtx, err := bfv.NewBfvContextWithParam(params.Params.N, params.Params.T, params.Params.Qi, params.Params.Pi, params.Params.Sigma)
	if err != nil {
		return fmt.Errorf("recieved invalid parameter set")
	}

	crsGen, _ := dbfv.NewCRPGenerator([]byte{'l','a', 't', 't', 'i', 'g', 'o'}, bfvCtx.GetContextQ())
	ckg := dbfv.NewCKG(bfvCtx.GetContextQ(), crsGen.Clock())

	//get si
	sk, err := utils.GetSecretKey(bfvCtx)
	if err != nil {
		return fmt.Errorf("error when loading the secret key: %s", err)
	}
	//generate p0,i
	if ckg.GenShare(sk.Get()) != nil {
		return fmt.Errorf("cannot generate share: %s", err)
	}

	partial := ckg.GetShare()
	//if parent get share from child and aggregate
	if !ckgp.IsLeaf() {
		for i := 0; i < len(ckgp.Children()); i++ {
			child :=  <-ckgp.ChannelPublicKeyShares
			log.Printf("Got a share from children : %v, type : %T", child.PublicKeyShare,child)
			err = ckg.AggregateShares([]*ring.Poly{&child.PublicKeyShare.Poly})
			if err != nil{
				log.Printf("Error on share aggregations : %s ", err)
			}
		}
	}

	//send to parent
	log.Printf("Sending to parent %v", partial)
	err = ckgp.SendToParent(&PublicKeyShare{*partial}) // has no effect for root node
	if err != nil {
		return err
	}

	//propagate down the tree.
	log.Printf("Propagating down the tree")
	var ckg_0 ring.Poly
	if ckgp.IsRoot() {
		ckg_0 = *partial // if node is root, the combined key is the final collective key
	} else {
		ckg_0 = (<-ckgp.ChannelPublicKey).CKG_0 // else, receive it from parents
	}
	log.Printf("Down propagation to children..: %v", ckg_0)
	err = ckgp.SendToChildren(&PublicKey{CKG_0:ckg_0}) // forward the collective key to children
	if err != nil {
		return err
	}

	log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	return nil
}

//func (spks *PublicKeyShare) UnMarshalBinary(data []byte) (error) {
//	log.Printf("Using custom unmarshal")
//	N := uint64(int(1 << data[0]))
//	numberModulies := uint64(int(data[1]))
//
//	var pointer uint64
//
//	pointer = 2
//
//	if ((uint64(len(data)) - pointer) >> 3) != N*numberModulies {
//		return /* nil, */errors.New("error : invalid polynomial encoding")
//	}
//
//	if _, err := ring.DecodeCoeffs(pointer, N, numberModulies, spks.Coeffs, data); err != nil {
//		return /*nil,*/ err
//	}
//
//	return /*Pol,*/ nil
//}