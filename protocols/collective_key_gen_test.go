package protocols

import (
	"github.com/lca1/lattigo/bfv"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"testing"

	"time"
)


func TestCollectiveKeyGeneration(t *testing.T) {

	log.Lvl1("Started test")
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(3, true)

	pi, err := local.CreateProtocol("FVCollectiveKeyGeneration", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	ckgp := pi.(*CollectiveKeyGenerationProtocol)
	ckgp.Params = bfv.DefaultParams[0]
	err = ckgp.Start()
	if err != nil{
		t.Fatal("Could not start the tree : " , err)
	}
	log.Lvl2("Collective Key Generated")

	<- time.After(time.Second) // Leave some time for children to terminate
	local.CloseAll()
}
