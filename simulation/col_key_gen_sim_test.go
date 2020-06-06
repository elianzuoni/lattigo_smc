package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

//Simulate the collective key generation. With a test.
func TestSimulationCollectiveKeyGen(t *testing.T) {
	//turn off test variable
	log.Lvl1("Test !! ")

	simul.Start("runconfigs/key_gen_config.toml")

	return
}
