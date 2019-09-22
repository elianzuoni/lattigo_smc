package protocols

import (
	"github.com/lca1/lattigo/bfv"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	ex "protocols/examples"
	"testing"
	"time"
)


func TestCollectiveKeyGeneration(t *testing.T) {
	nbnodes := 3
	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("FVCollectiveKeyGeneration", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	ckgp := pi.(*CollectiveKeyGenerationProtocol)
	ckgp.Params = bfv.DefaultParams[0]
	log.Lvl1("Starting ckgp")
	err = ckgp.Start()
	if err != nil{
		t.Fatal("Could not start the tree : " , err)
	}
	log.Lvl1("Collective Key Generated")

	<- time.After(time.Second) // Leave some time for children to terminate
	//time.Sleep(time.Second)

	ckgp.Shutdown()
	local.CloseAll()



}



func TestLocalCollectiveKeyGeneration(t *testing.T){
	log.Lvl1("Starting to test key genereation locally")
	//TODO how to check locally ? ~ make keygen without nodes ?
	ex.Main()

}