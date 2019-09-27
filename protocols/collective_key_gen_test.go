package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	ex "protocols/examples"
	"protocols/utils"
	"testing"
	"time"
)


func TestLocalCollectiveKeyGeneration(t *testing.T) {
	nbnodes := 30
	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	local := onet.NewLocalTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectiveKeyGeneration", tree)
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

	log.Lvl1("Collective Key Generated for " ,len(ckgp.Roster().List) , " nodes.\n\tNow comparing all polynomials.")

	//check if we have all the same polys ckg_0
	keys := make([]ring.Poly,len(ckgp.Roster().List))

	for i := 0 ; i < len(ckgp.Roster().List); i++{
		//get the keys.
		pk :=( <- ckgp.ChannelPublicKey).Poly
		keys[i] = pk
	}
	for _,k1 := range(keys){
		for _, k2 := range(keys){
			err := utils.ComparePolys(k1,k2)
			if err != nil{
				log.Error("Error in polynomial comparison : ", err)
			}
		}
	}


	<- time.After(time.Second)

	log.Lvl1("Success")
	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	//local.CloseAll()
	 */


}

//same as local except we use TCP. 
func TestLocalTCPCollectiveKeyGeneration(t *testing.T){

	nbnodes := 3
	log.Lvl1("Started to test key generation on a simulation with nodes amount : ", nbnodes)
	local := onet.NewTCPTest(suites.MustFind("Ed25519"))
	defer local.CloseAll()

	_, _, tree := local.GenTree(nbnodes, true)

	pi, err := local.CreateProtocol("CollectiveKeyGeneration", tree)
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

	log.Lvl1("Collective Key Generated for " ,len(ckgp.Roster().List) , " nodes.\n\tNow comparing all polynomials.")

	//check if we have all the same polys ckg_0
	keys := make([]ring.Poly,len(ckgp.Roster().List))

	for i := 0 ; i < len(ckgp.Roster().List); i++{
		//get the keys.
		pk :=( <- ckgp.ChannelPublicKey).Poly
		keys[i] = pk
	}
	for _,k1 := range(keys){
		for _, k2 := range(keys){
			err := utils.ComparePolys(k1,k2)
			if err != nil{
				log.Error("Error in polynomial comparison : ", err)
			}
		}
	}

	<- time.After(time.Second) // Leave some time for children to terminate

	/*TODO - make closing more "clean" as here we force to close it once the key exchange is done.
			Will be better once we ca have all the suites of protocol rolling out. We can know when to stop this protocol.
	Ideally id like to call this vvv so it can all shutdown outside of the collectivekeygen
	//local.CloseAll()
	*/
}





func TestAllCollectiveKeyGeneration(t *testing.T){
	log.Lvl1("Starting to test key genereation locally")
	//TODO how to check locally ? ~ make keygen without nodes ?
	ex.Main()

}