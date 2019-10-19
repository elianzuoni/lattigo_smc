package main

import (
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul"
)

func main() {
	log.SetDebugVisible(1)
	simul.Start()
}
