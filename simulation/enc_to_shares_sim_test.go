package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

//Simulate the collective key generation. With a test.
func TestEncToSharesSimulation(t *testing.T) {
	log.SetDebugVisible(1)

	simul.Start("runconfigs/enc_to_shares_config.toml")

	return
}
