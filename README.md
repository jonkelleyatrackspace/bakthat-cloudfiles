# bakthat - with Rackspace swift (cloudfiles) support.
This tool has the option to upload compressed copies of files into a cloudfiles container account.
Some features of the suite:
* Uses swift-common client.py implementation which improves performance and reliability over the issues commonly brought up about duplicity.
* Compresses all of the files with gzip before sending.
* Has option to encrypt with a password (blowfish+aes) with pycrpto library.
* Restoration of files from cloudfiles to local disk is supported.
* List, Delete, Backup, and Restore currently supported.
* bakthat can be hooked as a module so you can write your own scripts, or use mine- filewalker.py


## What are the requirements?
* Python 2.6 or 2.7 tested.
* Install gcc, make, and the python devel libraries with your favorite package manager.
* `easy_install pip` if you do not already have pip installed with your python distribution.
* You will need to install the modules required via pip `pip install -r reqs.txt`
Modules: ```aaargh
beefish
pycrypto
boto
python-swiftclient```

# What do these .py files do?
## bakthatswift.py
This contains the core classes for crypto, compression, and the wrapper for the swift common client. It acts as a module and as a standalone application. It's a fork of a project called bakthat (https://github.com/tsileo/bakthat) and I have plans to push my changes back into the original software when I get in touch with the author.

### Sample bakthatswift.conf
```[cf]
apiuser = USER
apikey = KEY
container = CONTAINER
region_name = dfw
```
(NOTE: For now, for this application to work, you need to also configure classauth.conf with matching api key settings.)

## classauth.py
Handles the authentication for cloudfiles library. It caches the auth token to disk locally to increase speed performance.

Known problems:
You must make the config file (below) match the credentials you have configured in either filewalker.conf or bakthatswift.conf.

### Sample classauth.conf
```[usa]
auth_url = https://identity.api.rackspacecloud.com/v2.0/tokens
username = user
apikey = key
json_cache_pckl_file = /tmp/authkey.usa.pckl

[lon]
auth_url = https://identity.api.rackspacecloud.com/v2.0/tokens
username = user
apikey = key
json_cache_pckl_file = /tmp/authkey.lon.pckl
```

## filewalker.py
This file can walk files within a directory and only back up files older then a time in seconds. It can automatically delete the
local copy after the remote end is uploaded with a verified md5sum. This script will also refuse to overwrite an existing filename
on cloudfiles, and will skip the local backup after logging the error.

You can use this helper script if you don't want to write your own apps/shell script to utilize bakthatswift.py.

###Sample filewalker.conf
```[filewalker]
backup_age = 1  # How many seconds before this is applicable for a backup?
delete_afterwards = True # Should we delete after verifying remote md5?
backup_source = ~/backups/ 
backup_password = test

[cloudfilesSettings]
apiuser = user
apikey = key
container = test
region_name = dfw
```

### Command examples:
#### Execute a backup WITHOUT PERFORMING ANY OPERATION, use this first!
python2.7 filewalker.py backup --config filewalker.conf --noop true

####  Execute a backup based on your settings:
python2.7 filewalker.py backup --config filewalker.conf

####  Restore a backup from remote end.
Remember to add .enc if it is an encrypted file!
You will be asked for the crypto password, and the file will be extracted in the local directory.
python2.7 filewalker.py restore -f name-of-file.bz2.tgz.enc --config filewalker.conf

# Command examples
## filewalker.py
### Run a backup in test mode (zero action taken)
PRO-TIP: Adding --noop with any value after it causes no-op to take effect.
 filewalker.py backup --config filewalker.conf --noop true`

### Run a backup against the configured directory.
`/usr/bin/env python filewalker.py backup --config filewalker.conf`

### Run a restore.
`/usr/bin/env python filewalker.py restore --config filewalker.conf -f remote-filename-to-restore`

## bakthatswift.py
### Run interactive config setup.
`/usr/bin/env python bakthatswift.py configure`

### Backup a file explicitly.
`/usr/bin/env python bakthatswift.py backup -c bakthatswift.conf -f filename-to-backup`

### Restore a file.
`/usr/bin/env python bakthatswift.py restore -c bakthatswift.conf -f filename-to-restore`

### Delete a file in the container:
`/usr/bin/env python bakthatswift.py delete -c bakthatswift.conf -f remote-file-to-delete`

### List files in container.
`/usr/bin/env python bakthatswift.py ls -c bakthatswift.conf`

### Retrieve md5 for explicit file in container.
`/usr/bin/env python bakthatswift.py md5 -c bakthatswift.conf -f filename-for-wanted-md5-value`

## When will this be ported to bakthat main project?
I will need to get an Amazon account and do cross-service level testing when I get a chance in my spare time to backport this to the original codebase. However, it is possible and should be simple.

