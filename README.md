### bakthat - with swift support.
This tool has the option to upload compressed copies of files into a cloudfiles container account.
It can also:
	* Encrypt using with a password (uses aes and blowfish combined using pycrpto library)
	* Restore files from the remote end (and decrypt)
	* List files in cloudfiles (gets name, md5sum, bytesize)
	* Hooks as a module so you can do stuff with your own scripts using its internal class methods.

## Get the environment ready.
This should work on Python 2.6 - 2.7
You will need pip installed. You will need gcc, make, and the python-dev package installed for modules to compile.

To install the module dependecies run `pip install -r reqs.txt`
	

## Explanation of the utilities:
# bakthatswift.py
This contains the core classes for crypto, compression, and the wrapper for the swift common client. It acts as a module and as a standalone application. It's a fork of a project called bakthat (https://github.com/tsileo/bakthat) and I have plans to push my changes back into the original software when I get in touch with the author.

Reads config from bakthatswift.conf, example config:
[cf]
apiuser = USER
apikey = KEY
container = CONTAINER
region_name = dfw
(NOTE: For now, for this application to work, you need to also configure classauth.conf with matching api key settings.)

# classauth.py
Handles the authentication for cloudfiles library. It caches the auth token to disk locally to increase speed performance.

Reads config from classauth.conf, example config:
[usa]
auth_url = https://identity.api.rackspacecloud.com/v2.0/tokens
username = user
apikey = key
json_cache_pckl_file = /tmp/authkey.usa.pckl

[lon]
auth_url = https://identity.api.rackspacecloud.com/v2.0/tokens
username = user
apikey = key
json_cache_pckl_file = /tmp/authkey.lon.pckl

# filewalker.py
This file can walk files within a directory and move files older then a time in seconds. It can automatically delete the
local copy after the remote end is uploaded with a verified md5sum. This script will also refuse to overwrite an existing filename
on cloudfiles, and will skip the local backup after logging the error.

You can execute this directly if you don't want to write your own apps to utilize bakthatswift.py.

Sample filewalker.conf
[filewalker]
backup_age = 1  # How many seconds before this is applicable for a backup?
delete_afterwards = True # Should we delete after verifying remote md5?
backup_source = ~/backups/ 
backup_password = test


[cloudfilesSettings]
apiuser = user
apikey = key
container = test
region_name = dfw

## Command examples:
# Execute a backup WITHOUT PERFORMING ANY OPERATION, use this first!
python2.7 filewalker.py backup --config filewalker.conf --noop true

# Execute a backup based on your settings:
python2.7 filewalker.py backup --config filewalker.conf

# Restore a backup from remote end.
# Remember to add .enc if it is an encrypted file!
# You will be asked for the crypto password, and the file will be extracted in the local directory.
python2.7 filewalker.py restore -f name-of-file.bz2.tgz.enc --config filewalker.conf









pip-2.6 install aaargh
yum install gcc make python26-devel
pip-2.6 install beefish pycrypto boto python-cloudfiles 

cd /opt
git clone git://github.com/jonkelleyatrackspace/cloudbackup.git
cd cloudbackup

