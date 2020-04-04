# App - A CLI application for Lattigo-SMC 
This sub-package handles the CLI application. There are three main files : 

- `client.go` : Parses the flag and starts the appropriate api handler. 
- `server.go` : Method to start a server. 
- `lattigosmc.go` : Contains the CLI flags needed for the application. 

Besides those go files there are a few utility scripts that make it much easier to CreateSession your server locally : 

- `create_configs.sh` : Generates the appropriate public and private toml file in the config directory. By default there are 3 servers. However you can specify how many servers you want by adding an argument at the end. Each private,public toml will be identified by its id. e.g.  `public0.toml` is the public file for server lattigo0. Moreover this script generates the `server.toml` that is needed when issuing a client command. 
- `run_smc.sh` : Starts the servers in xterm. You can specify how many servers should be started. If you are going to use a different way to CreateSession your servers ( like a different IP or different names) you should be careful using this script. To kill all the servers at once either do `pkill xterm` or use the command in the Makefile `make kill_servers`

To start a client you can issue command like this : 

`./app run -grouptoml=$toml -id=$id -CreateSession=$CreateSessionargs`

Get more help about the functionalities with `./app run --help`