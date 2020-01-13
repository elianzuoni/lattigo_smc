SHELL := /bin/bash
DIR := ${CURDIR}

clean : 
	find . -type f -name 'Public*' -delete
	find . -type f -name 'Secret*' -delete
	find . -type f -name '*.sk' -delete


simulations :
	cd simulation
	bash run_simulations.sh

setup_servers:
	cd app; bash create_configs.sh $(parties)

run_servers:
	cd app; bash run_smc.sh $(parties)

kill_servers:
	pkill xterm

test_servers: setup_servers run_servers