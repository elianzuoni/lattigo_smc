package simulation

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

func TestMain(m *testing.M){
	log.MainTest(m)
}

func TestSimulationCollectiveKeyGen(t *testing.T){
	log.SetDebugVisible(3)
	simul.Start("key_gen_config.toml")
}
