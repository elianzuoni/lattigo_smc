package simulation

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
	"time"
)

func TestMain(m *testing.M){
	log.MainTest(m)
}

func TestSimulationCollectiveKeyGen(t *testing.T){
	log.SetDebugVisible(1)
	simul.Start("key_gen_config.toml")

	<- time.After(time.Second*5)


	return
}
