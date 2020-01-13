package main

import (
	"errors"
	"github.com/urfave/cli"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
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
	cliApp.Usage = "Homomorphic encryption based secure multi-party protocol application"

	debugFlags := []cli.Flag{
		cli.IntFlag{Usage: "logging-level : 1 to 5", Name: "debug,d", Value: 1},
	}
	clientFlags := []cli.Flag{
		cli.StringFlag{Name: "write, w", Usage: "Store data <data>"},
		cli.StringFlag{Name: "get, g", Usage: "Get data stored at <UUID>"},
		cli.StringFlag{Name: "retrievekey", Usage: "Retrieve key with boolean <collkey>,<evalkey>,<rottype>,<rotType>,<K>"},
		cli.StringFlag{Name: "grouptoml, gt", Usage: "Give the gorup toml"},
		cli.IntFlag{Name: "id", Usage: "id of the client"},

		cli.StringFlag{Name: "sum ,s", Usage: "Get sum of two ciphers comma separated : <id1>,<id2>"},

		cli.StringFlag{Name: "multiply ,m", Usage: "Get product of two ciphers comma separeted : <id1>,<id2>"},
		cli.StringFlag{Name: "refresh, ref", Usage: "Refresh a ciphertext with <UUID>"},
		cli.StringFlag{Name: "relin, rel", Usage: "Relinearize a cipher with <UUID>"},
		cli.StringFlag{Name: "rotate , rot", Usage: "Rotate a ciphertext format <UUID>,<rotType>,<K>"},
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
						app.InteractiveConfig(utils.SUITE, Name)
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
