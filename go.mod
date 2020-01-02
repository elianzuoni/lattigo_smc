module lattigo-smc

go 1.13

replace github.com/ldsec/lattigo => ../lattigo

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/ldsec/lattigo v0.0.0-00010101000000-000000000000
	github.com/urfave/cli v1.22.2
	go.dedis.ch/kyber/v3 v3.0.4
	go.dedis.ch/onet/v3 v3.0.21
	golang.org/x/text v0.3.2 // indirect
	gopkg.in/satori/go.uuid.v1 v1.2.0
)
