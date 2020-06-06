package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
)

func TestSimulationRotationKey(t *testing.T) {
	log.SetDebugVisible(1)

	simul.Start("runconfigs/rotation_key_config.toml")

	return
}
