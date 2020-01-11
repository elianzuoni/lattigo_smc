package main

import (
	"github.com/urfave/cli"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
)

//runServer runs the server.
func runServer(ctx *cli.Context) error {
	config := ctx.String("config")
	log.Lvl1("Config file :", config)
	app.RunServer(config)
	return nil
}
