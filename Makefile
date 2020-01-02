# Remove the keys file..

clean : 
	find . -type f -name 'Public*' -delete
	find . -type f -name 'Secret*' -delete
	find . -type f -name '*.sk' -delete


simulations :
	cd simulation
	bash run_simulations.sh