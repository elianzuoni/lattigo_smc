package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
	"time"
)

func TestSimulationCollectiveKeySwitch(t *testing.T) {
	log.SetDebugVisible(1)

	simul.Start("runconfigs/key_switch_config.toml")

	<-time.After(time.Second * 4)

	return
}
