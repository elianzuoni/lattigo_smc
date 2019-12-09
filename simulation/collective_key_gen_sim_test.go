package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"lattigo-smc/protocols"
	"testing"
)

//Simulate the collective key generation. With a test.
func TestSimulationCollectiveKeyGen(t *testing.T) {
	log.SetDebugVisible(1)
	//turn off test variable
	protocols.TurnOffTest()

	simul.Start("runconfigs/key_gen_config.toml")

	return
}
