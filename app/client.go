package main

import (
	"errors"
	"github.com/urfave/cli"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/services"
	"lattigo-smc/utils"
	"os"
	"strconv"
	"strings"
)

type SetupValues struct {
	paramsIdx    int
	genPublicKey bool
	genEvalKey   bool
	genRotKey    bool
	rotIdx       int
	K            uint64
}

func runLattigo(c *cli.Context) {
	//Setups
	groupToml := c.String("grouptoml")
	id := c.Int("id")
	setup := c.String("setup")
	retrieveKey := c.String("retrievekey")

	//Write-Read
	write := c.String("write")
	typeData := c.String("type")
	get := c.String("get")

	//Evaluations
	sum := c.String("sum")
	multiply := c.String("multiply")
	refresh := c.String("refresh")
	relin := c.String("relin")
	rotate := c.String("rotate")

	//Setups
	//setup the group toml for servers...
	if groupToml == "" {
		groupToml = "server.toml"
		log.Lvl1("Using default grouptoml :", groupToml)
	}
	roster, err := parseGroupToml(groupToml)
	if err != nil {
		log.ErrFatal(err, "Could not parse group toml file :", groupToml)
	}

	client := services.NewLattigoSMCClient(roster.List[id], string(id))

	if setup != "" {
		log.Lvl1("Setup request")

		values := parseSetup(setup)
		seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}
		err := client.SendSetupQuery(roster, values.genPublicKey, values.genEvalKey, values.genRotKey, uint64(values.rotIdx), int(values.K), uint64(values.paramsIdx), seed)
		if err != nil {
			log.Error("Could not setup the client :", err)
		}
	}
	if retrieveKey != "" {
		log.Lvl1("Request to get keys")
		values := strings.Split(retrieveKey, ",")
		genPublicKey, _ := strconv.ParseBool(values[0])
		genEvalKey, _ := strconv.ParseBool(values[1])
		genRotKey, _ := strconv.ParseBool(values[2])
		rotIdx, _ := strconv.ParseInt(values[3], 10, 32)
		d, err := client.SendKeyRequest(genPublicKey, genEvalKey, genRotKey, int(rotIdx))
		if err != nil {
			log.Error("Could not retrieve keys : ", err)
		}
		log.Lvl1("Retrieved the requested keys. ", d)

	}

	if write != "" {
		if typeData == "" {
			typeData = "string"
		}

		log.Lvl1("Request to write to server type of data : ", typeData)
		var err error
		var id *uuid.UUID
		if typeData == "string" {
			id, err = client.SendWriteQuery(roster, []byte(write))
		} else if typeData == "byte" {
			data := strings.Split(write, ",")
			dBytes := utils.StringToBytes(data)
			id, err = client.SendWriteQuery(roster, dBytes)
		} else {
			log.Error("unknown type of data : ", typeData)
			return
		}
		if err != nil {
			log.Error("Could not write data : ", err)
			return
		}
		log.Lvl1("Wrote data at id : ", id)
		return

	}
	if get != "" {
		log.Lvl1("Request to get data from server")
		id, err := uuid.FromString(get)
		if err != nil {
			log.Error("Incorrect UUID :", err)
			return
		}
		data, err := client.GetPlaintext(&id)
		if typeData == "string" {
			log.Lvl1("Retrieved data at id ", id, " : ", string(data))

		} else {
			log.Lvl1("Retrieved data at id ", id, " : ", (data))

		}
		return
	}

	if sum != "" {
		log.Lvl1("Query to sum values on the root")
		values := strings.Split(sum, ",")
		if len(values) != 2 {
			log.Error("Invalid input expected two id comma separated got ", values)
			return
		}
		id1, err := uuid.FromString(values[0])
		if err != nil {
			log.Error("incorrect id ", err)
		}
		id2, err := uuid.FromString(values[1])
		if err != nil {
			log.Error("incorrect id ", err)
		}

		res, err := client.SendSumQuery(id1, id2)
		if err != nil {
			log.Error("Could not send sum query : ", err)
			return
		}
		log.Lvl1("Sum is stored at id ", res)

		return

	}
	if multiply != "" {
		log.Lvl1("Query to multiply  on the root")
		values := strings.Split(sum, ",")
		if len(values) != 2 {
			log.Error("Invalid input expected two id comma separated got ", values)
			return
		}
		id1, err := uuid.FromString(values[0])
		if err != nil {
			log.Error("incorrect id ", err)
		}
		id2, err := uuid.FromString(values[1])
		if err != nil {
			log.Error("incorrect id ", err)
		}

		res, err := client.SendMultiplyQuery(id1, id2)
		if err != nil {
			log.Error("Could not send multiply query : ", err)
			return
		}
		log.Lvl1("Multiply is stored at id ", res)

		return

	}

	if refresh != "" {
		log.Lvl1("Query to refresh values on the root")

		id, err := uuid.FromString(refresh)
		if err != nil {
			log.Error("incorrect id ", err)
		}

		res, err := client.SendRefreshQuery(&id)
		if err != nil {
			log.Error("Could not send refresh query : ", err)
			return
		}
		log.Lvl1("Refresh is stored at id ", res)

		return
	}

	if relin != "" {
		log.Lvl1("Query to relinearize a cipher")
		id, err := uuid.FromString(relin)
		if err != nil {
			log.Error("incorrect id ", err)
		}

		res, err := client.SendRelinQuery(id)
		if err != nil {
			log.Error("Could not send relin query : ", err)
			return
		}
		log.Lvl1("Relinearized cipher is stored at id ", res)

		return
	}

	if rotate != "" {
		log.Lvl1("Query to rotate a cipher")
		values := strings.Split(rotate, ",")

		id, err := uuid.FromString(values[0])
		if err != nil {
			log.Error("incorrect id ", err)
			return
		}

		K, err := strconv.ParseInt(values[1], 10, 32)
		if err != nil {
			log.Error("Could parse K ", err)
			return
		}

		rotType, err := strconv.ParseInt(values[2], 10, 32)
		if err != nil {
			log.Error("Could not parse rotation type ", err)
			return
		}

		res, err := client.SendRotationQuery(id, uint64(K), int(rotType))
		if err != nil {
			log.Error("Could not send rotate query : ", err)
			return
		}
		log.Lvl1("Rotated cipher is stored at id ", res)

		return
	}

}

func parseSetup(s string) SetupValues {
	values := strings.Split(s, ",")
	if len(values) != 6 {
		return SetupValues{}
	}
	paramsIdx, _ := strconv.ParseInt(values[0], 10, 32)
	genPublicKey, _ := strconv.ParseBool(values[1])
	genEvalKey, _ := strconv.ParseBool(values[2])
	genRotKey, _ := strconv.ParseBool(values[3])
	rotIdx, _ := strconv.ParseInt(values[4], 10, 32)
	K, _ := strconv.ParseUint(values[5], 10, 64)
	sv := SetupValues{
		paramsIdx:    int(paramsIdx),
		genPublicKey: genPublicKey,
		genEvalKey:   genEvalKey,
		genRotKey:    genRotKey,
		rotIdx:       int(rotIdx),
		K:            K,
	}

	return sv
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
