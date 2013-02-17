""" Backups up encrypted (or not) and supports recursion into any directory as long as the file meets
    the minumum backup age.
    
    Also supports deleting file from local disk afterwards.
    Before deleting the local copy it verifies the remote md5sum.

 -- jon kelley Feb, 5, 2012
"""

"""
This requires a config file passed as a command line arguement.
    
[filewalker]
backup_age          = 3
delete_afterwards   = True
backup_source       = /backup/
backup_password = test

[cloudfilesSettings]
apiuser         = 
apikey          = 
container       = CFTestContainer
region_name     = ord


Sample command usage:
    -- config   loads config files
    -- noop     causes no actions to take.
    
    == Sample what will be backed up using `config` ==
    python backupfiles_filewalker.py backup --config config --noop True
    
    == Back up ==
    python backupfiles_filewalker.py backup --config config
    
    == Restore file `filename`, you will be asked for crypto password ==
    python backupfiles_filewalker.py restore --config config -f filename
"""
import aaargh, ConfigParser
config = ConfigParser.SafeConfigParser()
app = aaargh.App(description="Handles backups for stuff")


import fnmatch, os, time
now = time.time()           # cur time

import bakthatswift
from bakthatswift import SwiftBackend

import classlog as log


def isdirectory(file):
    """ Just helps to return if file is a directory or not """
    try:
        if os.path.isdir(file):
            return True
        else:
            return False
    except OSError as err:
        print(err)

def return_files_under_path(d):
    """ Returns all files (no directories) within a particular directory tree. Just recurses through """
    #return [os.path.join(d, f) for f in os.listdir(d)]  << This would just return all files under path,,, without recursing...
    files = []
    try:
        for f in os.listdir(d):
            file = os.path.join(d, f)
            if isdirectory(file): # < But we want to recurse.
                files = files + return_files_under_path(file)
            else:
                if len(file) != 0:
                    files.append(file)
    except OSError as err:
        print(err)

    return files


def file_older_than(maxage,file):
    """ Just determines if a file is older then config param. """
    import time
    now = time.time()
    try:
        then = os.path.getmtime(file)
        age  = now-then

        if age >= maxage:
            return True
        else:
            return False
    except OSError as err:
        print(err)

@app.cmd(help="Backs everything up.")
@app.cmd_arg('-c', '--configfile', type=str)
@app.cmd_arg('-z', '--noop', type=str, default=None)
def backup(configfile,noop):
    if not configfile:
        raise Exception("\n\nMissing -c option for config file.")
    else:
        config.read(os.path.expanduser(configfile))

    backup_source          = str(config.get("filewalker", "backup_source"))
    if not backup_source.endswith('/'):
        raise Exception("\n\nMissing trailing slash for backup path:\n backup_loc: %s" % backup_loc)
    backup_age              = int(config.get("filewalker", "backup_age"))
    
    delete_afterwards       = config.get("filewalker", "delete_afterwards")
    if delete_afterwards == "True": delete_afterwards = True
    else: delete_afterwards = False

    if noop:
        print "--noop detected, no actions being taken."
    files = return_files_under_path(backup_source)
    for file in files:
        if noop and file_older_than(backup_age, file): # Just print out test operation.
                print "NOOP Backup: " + file
                if delete_afterwards:
                    print "NOOP Delete: " + file
        else:
            if file_older_than(backup_age, file):
                if perform_backup(file): # If the backup process returns true.
                    if delete_afterwards:
                        perform_delete(file)


def perform_delete(file):
    """ Deletes a file, accepts 1 arguement: the file you wish to destroy """
    """ TODO Check remote end for existance before deletion """
    try:
        log.instance.logger.info("Deleting " + str(file), exc_info=True)
        os.unlink(file) # bye
    except OSError as err:
        print(err)

def perform_backup(file):
    apiuser     = config.get("cloudfilesSettings", "apiuser")
    apikey      = config.get("cloudfilesSettings", "apikey")
    container   = config.get("cloudfilesSettings", "container")
    region_name = config.get("cloudfilesSettings", "region_name")
    crypto_password = config.get("filewalker", "backup_password")
    """ Backups a file, accepts 1 arguement: the file you wish to backup """

    backup_constants = {"apiuser": apiuser,
                        "apikey": apikey,
                        "container": container,
                        "region_name": region_name,
                        "crypto_password": crypto_password }

    if bakthatswift.backup(file, conf=backup_constants, destination="cloudfiles"):
        return True
    else:
        return False


@app.cmd(help="Restores --filename")
@app.cmd_arg('-c', '--configfile', type=str)
@app.cmd_arg('-f', '--filename', type=str)
def restore(configfile,filename=None,cryptopass=None):
    if not configfile:
        raise Exception("\n\nMissing -c option for config file.")
    else:
        config.read(os.path.expanduser(configfile))

    if not filename:
        raise Exception("\n\nWhat remote filename to restore?!")

    restore_file(filename,cryptopass)
    print filename + " restored to CWD."

def restore_file(file,crytopass):
    apiuser     = config.get("cloudfilesSettings", "apiuser")
    apikey      = config.get("cloudfilesSettings", "apikey")
    container   = config.get("cloudfilesSettings", "container")
    region_name = config.get("cloudfilesSettings", "region_name")
    crypto_password = config.get("filewalker", "backup_password")
    backup_constants = {"apiuser": apiuser,
                        "apikey": apikey,
                        "container": container,
                        "region_name": region_name,
                        "crypto_password": crypto_password }

    bakthatswift.restore(file, conf=backup_constants, destination="cloudfiles")

def main():
    app.run()

if __name__ == '__main__':
    main()
