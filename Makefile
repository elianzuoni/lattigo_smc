# Remove the keys file..

clean : 
	find . -type f -name 'Public*' -delete
	find . -type f -name 'Secret*' -delete
