package app

import (
	"errors"
	"github.com/urfave/cli"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/services"
	"os"
)

func runLattigo(c *cli.Context) {
	//parameters
	data := c.String("write")
	groupToml := c.String("grouptoml")
	sum := c.Bool("sum")
	multiply := c.Bool("multiply")
	predict := c.Bool("predict")
	write := c.Bool("write")
	//setup the group toml for servers...

	_, err := parseGroupToml(groupToml)
	if err != nil {
		log.ErrFatal(err, "Could not parse group toml file :", groupToml)
	}

	if sum {

		log.Lvl1("Query to sum all values on the root")

	} else if multiply {
		log.Lvl1("Query to multiply all values on the root")
	} else if data != "" && write {
		log.Lvl1("Storing data : ", data, " on server ")
		//todo add check for data

	} else if data != "" && predict {
		log.Lvl1("Predicting for value : ", data)
		//todo add check for data.
	} else {
		log.Error("Error : bad argument combination")
	}

}

func parseGroupToml(s string) (*onet.Roster, error) {
	file, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	group, err := app.ReadGroupDescToml(file)
	if err != nil {
		return nil, err
	}
	if len(group.Roster.List) <= 0 {
		return nil, errors.New("Roster length should be > 0")
	}
	return group.Roster, nil
}

func writeQuery(el *onet.Roster, data string) error {
	entryPoint := el.List[0]
	client := services.NewLattigoSMCClient(entryPoint, "0")

	queryID, err := client.SendWriteQuery(el, []byte{' '})
	if err != nil {
		return err
	}
	result, err := client.GetWriteResult(queryID)

	return nil
}

func sumQuery() error {
	return nil
}

func multiplyQuery() error {
	return nil
}

func predictQuery() error {
	return nil
}
