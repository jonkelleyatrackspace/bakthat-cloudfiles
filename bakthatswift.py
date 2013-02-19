#!/usr/bin/python

#
"""
Copyright (c) 2012 Thomas Sileo
Copyright (c) 2012 Jon Kelley (cloudfiles support + other changes)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



./pycloudbackup.py backup -f testfile -p None 2>&1 | cut -d'=' -f3 | head -1
"""

import tarfile
import tempfile
import os
#import sys
import ConfigParser
from datetime import datetime
from getpass import getpass


import boto
from boto.s3.key import Key
import shelve
import boto.glacier
import boto.glacier.layer2
from boto.glacier.exceptions import UnexpectedHTTPResponseError
from beefish import decrypt, encrypt
import aaargh
import json


DEFAULT_LOCATION = "us-east-1"
DEFAULT_RACKSPACE_LOCATION = "ord" # other options = ord, lon

app = aaargh.App(description="Compress, encrypt and upload files directly to Rackspace Cloudfiles/Amazon S3/Glacier.")



config = ConfigParser.SafeConfigParser()
config.read(os.path.expanduser("bakthatswift.conf"))

class glacier_shelve(object):
    """
    Context manager for shelve
    """

    def __enter__(self):
        self.shelve = shelve.open(os.path.expanduser("~/.bakthat.db"))

        return self.shelve

    def __exit__(self, exc_type, exc_value, traceback):
        self.shelve.close()


class S3Backend:
    """
    Backend to handle S3 upload/download
    """
    def __init__(self, conf):
        if conf is None:
            try:
                access_key = config.get("aws", "access_key")
                secret_key = config.get("aws", "secret_key")
                bucket = config.get("aws", "s3_bucket")
                try:
                    region_name = config.get("aws", "region_name")
                except ConfigParser.NoOptionError:
                    region_name = DEFAULT_LOCATION
            except ConfigParser.NoOptionError:
                log.error("Configuration file not available.")
                log.info("Use 'bakthat configure' to create one.")
                return
        else:
            access_key = conf.get("access_key")
            secret_key = conf.get("secret_key")
            bucket = conf.get("bucket")
            region_name = conf.get("region_name", DEFAULT_LOCATION)

        con = boto.connect_s3(access_key, secret_key)
        if region_name == DEFAULT_LOCATION:
            region_name = ""
        self.bucket = con.create_bucket(bucket, location=region_name)
        self.container = "S3 Bucket: {}".format(bucket)

    def download(self, keyname):
        k = Key(self.bucket)
        k.key = keyname

        encrypted_out = tempfile.TemporaryFile()
        k.get_contents_to_file(encrypted_out)
        encrypted_out.seek(0)
        
        return encrypted_out

    def cb(self, complete, total):
        percent = int(complete * 100.0 / total)
        log.info("Upload completion: {}%".format(percent))

    def upload(self, keyname, filename, cb=True):
        k = Key(self.bucket)
        k.key = keyname
        upload_kwargs = {}
        if cb:
            upload_kwargs = dict(cb=self.cb, num_cb=10)
        k.set_contents_from_file(filename, **upload_kwargs)
        k.set_acl("private")

    def ls(self):
        return [key.name for key in self.bucket.get_all_keys()]

    def delete(self, keyname):
        k = Key(self.bucket)
        k.key = keyname
        self.bucket.delete_key(k)



class GlacierBackend:
    """
    Backend to handle Glacier upload/download
    """
    def __init__(self, conf):
        if conf is None:
            try:
                access_key = config.get("aws", "access_key")
                secret_key = config.get("aws", "secret_key")
                vault_name = config.get("aws", "glacier_vault")
                try:
                    region_name = config.get("aws", "region_name")
                except ConfigParser.NoOptionError:
                    region_name = DEFAULT_LOCATION
            except ConfigParser.NoOptionError:
                log.error("Configuration file not available.")
                log.info("Use 'bakthat configure' to create one.")
                return
        else:
            access_key = conf.get("access_key")
            secret_key = conf.get("secret_key")
            vault_name = conf.get("vault")
            region_name = conf.get("region_name", DEFAULT_LOCATION)

        con = boto.connect_glacier(aws_access_key_id=access_key,
                                    aws_secret_access_key=secret_key, region_name=region_name)

        self.conf = conf
        self.vault = con.create_vault(vault_name)
        self.backup_key = "bakthat_glacier_inventory"
        self.container = "Glacier vault: {}".format(vault_name)

    def backup_inventory(self):
        """
        Backup the local inventory from shelve as a json string to S3
        """
        d = glacier_shelve()
        if not d.has_key("archives"):
            d["archives"] = dict()
            archives = d["archives"]

        s3_bucket = S3Backend(self.conf).bucket
        k = Key(s3_bucket)
        k.key = self.backup_key

        k.set_contents_from_string(json.dumps(archives))

        k.set_acl("private")


    def restore_inventory(self):
        """
        Restore inventory from S3 to local shelve
        """
        s3_bucket = S3Backend(self.conf).bucket
        k = Key(s3_bucket)
        k.key = self.backup_key

        loaded_archives = json.loads(k.get_contents_as_string())

        d = glacier_shelve()
        if not d.has_key("archives"):
            d["archives"] = dict()

        archives = loaded_archives
        d["archives"] = archives


    def upload(self, keyname, filename):
        archive_id = self.vault.create_archive_from_file(file_obj=filename)

        # Storing the filename => archive_id data.
        d = glacier_shelve()
        if not d.has_key("archives"):
            d["archives"] = dict()

        archives = d["archives"]
        archives[keyname] = archive_id
        d["archives"] = archives

        self.backup_inventory()

    def get_archive_id(self, filename):
        """
        Get the archive_id corresponding to the filename
        """
        d = glacier_shelve()
        if not d.has_key("archives"):
            d["archives"] = dict()

        archives = d["archives"]

        if filename in archives:
            return archives[filename]

        return None

    def download(self, keyname):
        """
        Initiate a Job, check its status, and download the archive if it's completed.
        """
        archive_id = self.get_archive_id(keyname)
        if not archive_id:
            return
        
        d = glacier_shelve()
        if not d.has_key("jobs"):
            d["jobs"] = dict()

        jobs = d["jobs"]
        job = None

        if keyname in jobs:
            # The job is already in shelve
            job_id = jobs[keyname]
            try:
                job = self.vault.get_job(job_id)
            except UnexpectedHTTPResponseError: # Return a 404 if the job is no more available
                del job[keyname]

            if not job:
                # Job initialization
                job = self.vault.retrieve_archive(archive_id)
                jobs[keyname] = job.id
                job_id = job.id

            # Commiting changes in shelve
            d["jobs"] = jobs

        log.info("Job {action}: {status_code} ({creation_date}/{completion_date})".format(**job.__dict__))

        if job.completed:
            log.info("Downloading...")
            encrypted_out = tempfile.TemporaryFile()
            encrypted_out.write(job.get_output().read())
            encrypted_out.seek(0)
            return encrypted_out
        else:
            log.info("Not completed yet")
            return None

    def ls(self):
        d = glacier_shelve()
        if not d.has_key("archives"):
            d["archives"] = dict()

        return d["archives"].keys()

    def delete(self, keyname):
        archive_id = self.get_archive_id(keyname)
        if archive_id:
            self.vault.delete_archive(archive_id)
            d = glacier_shelve()
            archives = d["archives"]

            if keyname in archives:
                del archives[keyname]

            d["archives"] = archives

            self.backup_inventory()


import classauth    # The swift openstack doesn't support auth 2.0,
#                           #  nor does it seem to cache auth tokens.
import classlog as log      # Real logging saves real lives.
import swiftclient as files    # Hopefully this is a good binding.
#https://github.com/chmouel/python-swiftclient/blob/master/swiftclient/client.py
import hashlib

class SwiftBackend(object):
    """
    Backend to handle swift. 
        REFACTORED FOR PYRAX
           - by jon.kelley@rackspace.com
    """
    def __init__(self, conf):
        """ SWIFT COMMON CLIENT factored in """
        if conf is None:
            try:
                auth_user = config.get("cf", "apiuser")
                auth_key = config.get("cf", "apikey")
                self.container = config.get("cf", "container")
                try:
                    
                    region_name = config.get("cf", "region_name")
                    log.instance.logger.debug('Region set to config.get("cf", "region_name"):  ' + str(config.get("cf", "region_name")))
                except ConfigParser.NoOptionError:
                    region_name = DEFAULT_RACKSPACE_LOCATION
                    log.instance.logger.debug('Region set to DEFAULT_RACKSPACE_LOCATION:  ' + str(DEFAULT_RACKSPACE_LOCATION))
            except ConfigParser.NoOptionError:
                log.instance.logger.error("Configuration file not available.")
                log.instance.logger.error("Use 'bakthat configure' to create one.")
                return
        else:
            auth_user = conf.get("apiuser")
            auth_key = conf.get("apikey")
            self.container = conf.get("container")
            region_name = conf.get("region_name", DEFAULT_RACKSPACE_LOCATION)
            log.instance.logger.debug('Region set to DEFAULT_RACKSPACE_LOCATION:  ' + str(DEFAULT_RACKSPACE_LOCATION))

        # Authenticates with my auth module...
        self.auth        = classauth.identity('dfw')
        self.auth.url    = self.auth.get_endpoint('cloudFiles',region_name.upper()) # must be uppercase
        self.auth.token  = self.auth.get_token()

        self.create_container_if_not_exists(self.container)
        
    # ---------------------------------------------------------------------------------------------------
    # helper methods

    def create_container_if_not_exists(self,container):
        """ SWIFT CALL to create container if not exist. If container is created it returns true. """
        try:
            does_container_exist = files.get_container(self.auth.url,self.auth.token,container)
            log.instance.logger.debug('Container ``' + container + '`` exists already, skipping create... ')
            return False
        except files.client.ClientException:
            createcontainer = files.put_container(self.auth.url,self.auth.token,container)
            log.instance.logger.info('Container ``' + container + '`` doesnt exist, creating... ')
            return True

    def object_exists(self,container,object):
        """ Returns true if object exists, false if not """
        try:
            object = files.head_object(self.auth.url,self.auth.token,container,object)
            return True
        except:
            return False

    def return_md5_for_localfile(self,filedata):
        """ Takes a local file and uses hashlib to return result """
        m = hashlib.md5()
        while True:
            ## Don't read the entire file at once...
            data = filedata.read(10240)
            if len(data) == 0:
                break
            m.update(data)
        log.instance.logger.debug(' => md5 determined for local backup: ' + str(m.hexdigest()))
        return str(m.hexdigest())


    def return_md5_for_remotefile(self, keyname):
        """ SWIFT COMMON CLIENT factored in """
        """ Takes a objectname on cloudfiles and returns md5sum for remote file """
        header = files.head_object(self.auth.url,self.auth.token,self.container,keyname)
        return header['etag']

    #---------------------------------------------------------------------------------------------------------
    # end helper methods

    def download(self, file):
        object = files.get_object(self.auth.url,self.auth.token,self.container,file)
        headers = object [0] # The first element in tuple is the headers

        object = object[1]   # File data.
        
        encrypted_out = tempfile.NamedTemporaryFile()
        encrypted_out.write(object) # Write file data to temp file.
        encrypted_out.flush()

        encrypted_out.seek(0)
        return encrypted_out

#    def cb(self, complete, total):
        #?????????????
#        percent = int(complete * 100.0 / total)
#        log.info("Upload completion: {}%".format(percent))
#        print "unimplimented"

    def upload(self, remotefilename, filename, expectmd5=None, cb=False):
        """ SWIFT COMMON CLIENT factored in """
        if not self.object_exists(self.container,remotefilename):
            if expectmd5:
                files.put_object(self.auth.url,self.auth.token,self.container,remotefilename,filename)
                md5 = self.return_md5_for_remotefile(remotefilename)
                if md5 == expectmd5:
                    log.instance.logger.info('Upload success! MD5 of local and remote copy match ' + str(expectmd5))
                    return True
                else:
                    return False
            else: # In case your service class doesn't support md5 verification. Just fire and forget.
                files.put_object(self.auth.url,self.auth.token,self.container,remotefilename,filename)
                return True
        else: # Do not upload.
            log.instance.logger.error('Remote file ' + remotefilename + ' exists, we cant back up our local copy... skipping. ')
            return False

    def ls(self):
        """ SWIFT COMMON CLIENT factored in """
        full_filelist = [] # List which we'll page through until we get all filenames. We store all file metadata here in a list of dicts.
        objs = files.get_container(self.auth.url,self.auth.token,self.container,None,None,None,None,None,True)
        for obj in objs[1]: # For object in container data payload.
            try:
                bytes               = obj['bytes']
                last_modified       = obj['last_modified']
                hash                = obj['hash']
                name                = obj['name'] # Defines marker for last object in list, and filename for usage.
                marker              = name
                content_type        = obj['content_type']
                
                full_filelist.append({ 'name' : name, 'content_type' : content_type, 'last_modified' : last_modified , 'hash' : hash, 'bytes' : bytes })
            except:
                pass # Some of these objects are metadata.

        return full_filelist

    def md5(self, keyname):
        """ SWIFT COMMON CLIENT factored in """
        print self.ls()
        for object in self.ls():
            name = object['name']
            hash = object['hash']
            if name.startswith(keyname):
                return str(hash) + " : " + str(name)
            else:
                return "No object found for md5sum."


    def delete(self, keyname):
        """ REFACTORED FOR PYRAX """
        if not self.object_exists(self.container,keyname):
            log.instance.logger.warning('Cannot delete, file noexist: ' + str(keyname))
        else:
            print 'yyy'
            log.instance.logger.info('Remote delete for ' + str(keyname))
            files.delete_object(self.auth.url,self.auth.token,self.container,keyname)


storage_backends = dict(s3=S3Backend, glacier=GlacierBackend, cloudfiles=SwiftBackend)

@app.cmd(help="Backup a file or a directory, backup the current directory if no arg is provided.")
@app.cmd_arg('-f', '--filename', type=str, default=os.getcwd())
@app.cmd_arg('-d', '--destination', type=str, default="cloudfiles", help="s3|glacier|cloudfiles")
@app.cmd_arg('-p', '--password', type=str, default=None, help="Provide password non interactively.") # jonk nov 29 2012
def backup(filename, destination="cloudfiles", **kwargs):
    conf = kwargs.get("conf", None)
    storage_backend = storage_backends[destination](conf)


    arcname = filename.split("/")[-1]
    #stored_filename = arcname + datetime.now().strftime("%Y%m%d%H%M%S") + ".tgz"
    # filename file name date
    stored_filename = arcname + ".tgz"
    log.instance.logger.info("Backup started localname=" + filename + " remotename=" + str(stored_filename))
    password = kwargs.get("password")

    if conf is not None: # If the conf has been populated by using this as a module, set the password.
	    password = conf.get("crypto_password")
    else:
        if not password:
            password = getpass("Password (blank to disable encryption): ")

    log.instance.logger.info("Compressing... " + str(filename))
    out = tempfile.TemporaryFile()
#    with tarfile.open(fileobj=out, mode="w:gz") as tar:
#        tar.add(filename, arcname=arcname)

    tarz = tarfile.open(fileobj=out, mode="w:gz")
    tarz.add(filename, arcname=arcname)
    tarz.close()

    if password == "None" or password == "none":
        password = None

    if password:
        log.instance.logger.info("Encrypting... " + str(filename))
        encrypted_out = tempfile.TemporaryFile()
        encrypt(out, encrypted_out, password)
        stored_filename += ".enc"
        out = encrypted_out

    log.instance.logger.info(" => Getting md5 for " + str(filename))
    out.seek(0)
    md5 = str(storage_backend.return_md5_for_localfile(out))
    log.instance.logger.info("Uploading... " + str(filename))
    out.seek(0)
    if storage_backend.upload(stored_filename, out, md5):
        return True
        



@app.cmd(help="Set S3/Glacier/Cloudfiles credentials.")
def configure():
    configurechoice = input("What storage engine do you want to configure this to use?\n1. Rackspace Cloud Files\n2. Amazon AWS/Glacier\nEnter number: ")
    try:
        if configurechoice == 1:
            config.add_section("cf")
            config.set("cf", "apiuser", raw_input("Cloudfiles User: "))
            config.set("cf", "apikey", raw_input("Cloudfiles Key: "))
            config.set("cf", "container", raw_input("Cloudfiles Container: "))
            region_name = raw_input("Region Name (" + DEFAULT_RACKSPACE_LOCATION + "): ")
            if not region_name:
                region_name = DEFAULT_RACKSPACE_LOCATION
            config.set("cf", "region_name", region_name)

        elif configurechoice == 2:
            config.add_section("aws")
            config.set("aws", "access_key", raw_input("AWS Access Key: "))
            config.set("aws", "secret_key", raw_input("AWS Secret Key: "))
            config.set("aws", "s3_bucket", raw_input("S3 Bucket Name: "))
            config.set("aws", "glacier_vault", raw_input("Glacier Vault Name: "))
            region_name = raw_input("Region Name (" + DEFAULT_LOCATION + "): ")
            if not region_name:
                region_name = DEFAULT_LOCATION
            config.set("aws", "region_name", region_name)

        config.write(open(os.path.expanduser("~/.pycloudbackup.conf"), "w"))
        log.instance.logger.info("Config written in %s" % os.path.expanduser("~/.pycloudbackup.conf"))
    except ConfigParser.DuplicateSectionError:
        print "Duplicate section found in ~/.pycloudbackup.conf, delete this file if you want to make a new one. "



@app.cmd(help="Restore backup in the current directory.")
@app.cmd_arg('-f', '--filename', type=str, default="")
@app.cmd_arg('-d', '--destination', type=str, default="cloudfiles", help="s3|glacier|cloudfiles")
@app.cmd_arg('-p', '--password', type=str, default=None, help="Provide password non interactively.") # jonk nov 29 2012
def restore(filename, destination="cloudfiles", **kwargs):
    conf = kwargs.get("conf", None)

    storage_backend = storage_backends[destination](conf)

    if not filename:
        log.error("No file to restore, use -f to specify one.")
        return

    # Just some black magic to see if a string starting with our backup name is on cloudfiles.
    #   required, because sometimes we don't know if its encrypted or not.
    filename_found_in_swift = False
    for object in storage_backend.ls():
        objectname = object['name']
        if objectname.startswith(filename):
            filename_found_in_swift = objectname

    if filename_found_in_swift == False:
        log.instance.logger.error("Not found on cloudfiles. No file starting with " + str(filename) + " was found.")
    else:
        log.instance.logger.info("Restoring " + filename_found_in_swift)

        if filename_found_in_swift and filename_found_in_swift.endswith(".enc"):
            password = kwargs.get("password")
            if not password:
                password = getpass()
            elif password == "None":
                password = None

        log.instance.logger.info("Downloading... " + filename_found_in_swift)
        out = storage_backend.download(filename_found_in_swift)

        if out and filename_found_in_swift.endswith(".enc"):
            log.instance.logger.info("Decrypting... " + filename_found_in_swift)
            decrypted_out = tempfile.TemporaryFile()
            print decrypt(out, decrypted_out, password)

            out = decrypted_out
            log.instance.logger.debug("Decrypt filehandler= " + str(out))

        if out:
            log.instance.logger.info("Uncompressing... " + filename_found_in_swift)
            out.seek(0)
            tar = tarfile.open(fileobj=out)
            tar.extractall()
            tar.close()


@app.cmd(help="Delete a backup.")
@app.cmd_arg('-f', '--filename', type=str, default="")
@app.cmd_arg('-d', '--destination', type=str, default="cloudfiles", help="s3|glacier|cloudfiles")
def delete(filename, destination="cloudfiles", **kwargs):
    conf = kwargs.get("conf", None)
    storage_backend = storage_backends[destination](conf)

    if not filename:
        log.instance.logger.error("No file to delete, use -f to specify one.")
        return

#    found_file_to_delete = False
#    for object in storage_backend.ls():
#        objectname = object['name']
#        if objectname == filename:
#            found_file_to_delete = objectname
#            
#        if found_file_to_delete:
    storage_backend.delete(filename)
#        else:
#            log.instance.logger.error("No file " + str(filename) + " lives on this container.")
#            
#
#    keys = [name for name in storage_backend.ls() if name.startswith(filename)]
#    if not keys:
#        log.instance.logger.error("No file matched.")
#        return
#
#    key_name = sorted(keys, reverse=True)[0]
#    log.instance.logger.info("Deleting " + key_name)
#
#    storage_backend.delete(key_name)


@app.cmd(help="List stored backups.")
@app.cmd_arg('-d', '--destination', type=str, default="cloudfiles", help="s3|glacier|cloudfiles")
def ls(destination="cloudfiles", **kwargs):
    conf = kwargs.get("conf", None)
    storage_backend = storage_backends[destination](conf)

    log.instance.logger.info("REMOTE_CONTAINER: " + storage_backend.container)
    files = storage_backend.ls()
    for file in files:
        name = str(file['name'])
        hash = str(file['hash'])
        bytes = str(file['bytes'])
        last_modified = str(file['last_modified'])
        print ( "FILE: " + name + "     HASH: " + hash  + "BYTES: " + bytes + " LAST-MODIFIED: " + last_modified)


@app.cmd(help="Get an md5 of backup remotely.")
@app.cmd_arg('-f', '--filename', type=str, default="")
@app.cmd_arg('-d', '--destination', type=str, default="cloudfiles", help="cloudfiles")
def md5(filename, destination="cloudfiles", **kwargs):
    # Only supports cloudfiles, sorry AWS! I dunno how!
    conf = kwargs.get("conf", None)
    storage_backend = storage_backends[destination](conf)

    log.instance.logger.info("REMOTE_CONTAINER: " + storage_backend.container)
    files = storage_backend.return_md5_for_remotefile(filename)

    log.instance.logger.warn ( "Your md5sum is " + files )

@app.cmd(help="Backup Glacier inventory to S3")
def backup_glacier_inventory(**kwargs):
    conf = kwargs.get("conf", None)
    glacier_backend = GlacierBackend(conf)
    glacier_backend.backup_inventory()


@app.cmd(help="Restore Glacier inventory from S3")
def restore_glacier_inventory(**kwargs):
    conf = kwargs.get("conf", None)
    glacier_backend = GlacierBackend(conf)
    glacier_backend.restore_inventory()


def main():
    app.run()

if __name__ == '__main__':
    main()
