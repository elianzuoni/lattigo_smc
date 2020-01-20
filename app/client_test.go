package main

import (
	"go.dedis.ch/onet/v3/log"
	"os"
	"testing"
)

func TestClient(t *testing.T) {
	os.Args = []string{os.Args[0], "run", "--grouptoml=server.toml"}
	log.Lvl1("osArgs :", os.Args)
	main()
}
