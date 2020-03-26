package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

func TestEncToSharesSimulation(t *testing.T) {
	log.SetDebugVisible(1)

	simul.Start("runconfigs/enc_to_shares_config.toml")

	return
}
