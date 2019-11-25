package app

import (
	"errors"
	"github.com/urfave/cli"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"os"
)

const (
	Name    = "lattigo-smc"
	Version = "1.0.0"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = Name
	cliApp.Version = Version
	cliApp.Usage = "Homomorphic encryption based secure multi-party protocols"

	debugFlags := []cli.Flag{
		cli.IntFlag{Usage: "logging-level : 1 to 5", Name: "debug,d", Value: 1},
	}
	clientFlags := []cli.Flag{}
	serverFlags := []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Usage: "Configuration file of the server ",
		},
	}

	cliApp.Commands = []cli.Command{
		//Client run
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run Lattigo-smc client",
			Flags:   clientFlags,
		},

		//Server run
		{
			Name:  "server",
			Usage: "Start lattigo-smc server",
			Action: func(ctx *cli.Context) error {
				if err := runServer(ctx); err != nil {
					return errors.New("Error while running server : " + err.Error())
				}
				return nil
			},
			Flags: serverFlags,
			Subcommands: []cli.Command{
				{
					Name:    "setup",
					Aliases: []string{"s"},
					Action: func(ctx *cli.Context) error {
						log.Lvl1("Setting up lattigo server")
						app.InteractiveConfig(suites.MustFind("Ed25519"), Name)
						return nil
					},
				},
			},
		},
	}

	cliApp.Flags = debugFlags
	cliApp.Before = func(ctx *cli.Context) error {
		log.SetDebugVisible(ctx.GlobalInt("debug"))
		return nil
	}

	err := cliApp.Run(os.Args)
	if err != nil {
		log.ErrFatal(err, "Error while running app ")
	}
}
