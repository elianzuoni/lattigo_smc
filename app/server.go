package app

import (
	"github.com/urfave/cli"
	"go.dedis.ch/onet/v3/app"
)

//runServer runs the server.
func runServer(ctx *cli.Context) error {
	config := ctx.String("config")
	app.RunServer(config)
	return nil
}
