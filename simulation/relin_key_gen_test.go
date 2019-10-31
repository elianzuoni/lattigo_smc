package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
	"testing"
	"time"
)

//Simulate the collective key generation. With a test.
func TestSimulationRelinearizationKeyGen(t *testing.T) {
	log.SetDebugVisible(1)

	simul.Start("relin_key_config.toml")

	<-time.After(time.Second * 5)

	return
}
