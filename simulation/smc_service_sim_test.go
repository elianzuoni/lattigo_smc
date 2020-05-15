package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

func TestSMCSimulation(t *testing.T) {
	log.SetDebugVisible(3)

	simul.Start("runconfigs/smc_service_config.toml")

	return
}
