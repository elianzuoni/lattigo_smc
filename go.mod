module lattigo-smc

go 1.13

replace go.dedis.ch/onet/v3 => ../../../github.com/dedis/onet

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/golangplus/testing v0.0.0-20180327235837-af21d9c3145e
	github.com/ldsec/lattigo v1.3.1-0.20200505135144-ea718aa4ef84
	github.com/urfave/cli v1.22.2
	go.dedis.ch/kyber/v3 v3.0.12
	go.dedis.ch/onet/v3 v3.2.0
	go.dedis.ch/protobuf v1.0.11
	golang.org/x/lint v0.0.0-20190409202823-959b441ac422 // indirect
	golang.org/x/text v0.3.2 // indirect
	gopkg.in/satori/go.uuid.v1 v1.2.0
)
