package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

func TestProtocolsSimulation(t *testing.T) {
	log.SetDebugVisible(1)

	simul.Start("runconfigs/protocols_config.toml")

	return
}
