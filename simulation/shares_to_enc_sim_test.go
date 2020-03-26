package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

//Simulate the collective key generation. With a test.
func TestSharesToEncSimulation(t *testing.T) {
	log.SetDebugVisible(3)

	simul.Start("runconfigs/shares_to_enc_config.toml")

	return
}
