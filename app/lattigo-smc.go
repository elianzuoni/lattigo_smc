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
	clientFlags := []cli.Flag{
		cli.StringFlag{
			Name:  "write, w",
			Usage: "Store the data on the root",
			Value: "",
		},
		cli.BoolFlag{Name: "sum ,s", Usage: "Get sum of all data on the server"},
		cli.BoolFlag{Name: "multiply ,m", Usage: "Get product of all data on the server"},
		//todo see how we could do something like that.... maybe if the server has a trained vector
		cli.BoolFlag{Name: "predict, p", Usage: "Predict a value based on the data in the server"},
	}
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
			Action:  runLattigo,
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
						//This is the setup of onet. We do not need to do anything here.
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
