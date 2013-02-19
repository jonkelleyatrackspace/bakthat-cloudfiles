#!/usr/bin/env python2

import classlog
log = classlog   # logging is big

import ConfigParser, os # Tieing auth creds to config file.
config = ConfigParser.SafeConfigParser()
config.read(os.path.expanduser("classauth.conf"))
# We load all config values from this file.
# To configure this file on your system just run this command to inflate a skeleton config:
#cat >> classauth.conf << EOF
#[usa]
#auth_url = https://identity.api.rackspacecloud.com/v2.0/tokens
#username = username
#apikey = apikey
#json_cache_pckl_file = /tmp/authkey.usa.pckl
#[lon]
#auth_url = https://identity.api.rackspacecloud.com/v2.0/tokens
#username = username
#apikey = apikey
#json_cache_pckl_file = /tmp/authkey.lon.pckl
#EOF


AUTH_US_URL         = config.get("usa", "auth_url") # "https://identity.api.rackspacecloud.com/v2.0/tokens"
AUTH_US_USER        = config.get("usa", "username")
AUTH_US_KEY         = config.get("usa", "apikey")
AUTH_US_PCKL_FILE   = config.get("usa", "json_cache_pckl_file")

AUTH_UK_URL         = config.get("lon", "auth_url") # "https://lon.identity.api.rackspacecloud.com/v2.0/tokens"
AUTH_UK_USER        = config.get("lon", "username")
AUTH_UK_KEY         = config.get("lon", "apikey")
AUTH_UK_PCKL_FILE   = config.get("lon", "json_cache_pckl_file")

import aaargh       # Best ARG parsing library anywhere.
import time         # Because time is time, man.

# Auth
import pickle                   # Used for file-base serialized object access. Yeah.
import requestsd0390d4          # Requests by kennethreitz is a nice httplib wrapper, but rapidly changing codebase
import os, json                 # Obvious.
import time, dateutil.parser    # Used heavily in tokenexpired()


class AuthException(Exception):
    """ Used in cases when the parent module could try again """
    def __init__(self, value):
        print 'EXCEPTION_HANDLER!!:' + str(value)
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)

class AuthExceptionCritical(Exception):
    """ Used in cases when the parent module should give up, it's hopeless this can recover """
    def __init__(self, value):
        print 'EXCEPTION_HANDLER!!:' + str(value)
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)

class RSAuth:
    """A reusable class for retrieving auth info. It just goes out and grabs, nothing more, nothing less."""
    """ Congratulations, you found the hidden documentation on how to call upon RSAuth directly for auth data.
        We don't suggest you use this, because the identity class caches the data to disk for faster operation!!
        if __name__ == "__main__":
            auth = RSAuth('USA')
            print auth.get_token()                             # Prints a token
            print auth.get_endpoint('cloudFiles', 'DFW')     # Gets and endpoint
            print auth.rawobject                               # Prints the full json object.
    """
    def __init__(self,region):

        if region == 'USA':
            username        = AUTH_US_USER
            apikey          = AUTH_US_KEY
            auth_endpointurl=AUTH_US_URL
        if region == 'LON':
            username        = AUTH_UK_USER
            apikey          = AUTH_UK_KEY
            auth_endpointurl=AUTH_UK_URL
        if region == '':
            emsg="Region is defined as null! Why?? Expected [USA or LON] as arg to __init__"
            log.instance.logger.critical(emsg, exc_info=True)

        self.token = None
        self.expiration = None
        self.tenant_id = None
        self.headers = {'Content-Type': 'application/json', 'x-jon' : 'was here'}
        self.authurl = auth_endpointurl
        self.service_catalog = None
        


        
        # Does it!!
        self.authenticate(username, apikey, auth_endpointurl)

    def authenticate(self, username, apikey, auth_endpointurl, retries=0):
        print("rsauth.authenticate called")
        if retries >= 5:
            try:
                raise AuthExceptionCritical("Couldnt make request! Tried 5 times via requests lib and exausted.")
            except:
                log.instance.logger.critical("Auth failures are persistant. Tried 5 times. Failed.", exc_info=True)
        else:
            auth_payload = {
                "auth": {
                   "RAX-KSKEY:apiKeyCredentials": {  
                      "username": username,  
                      "apiKey": apikey
                   }
                }
            }

            log.instance.logger.info("Using auth target URL: POST " + str(auth_endpointurl))
            log.instance.logger.debug("Using auth payload: " + str(json.dumps(auth_payload)))
            log.instance.logger.debug("Using headers: " + str(self.headers))
            try:
                r = requestsd0390d4.post(auth_endpointurl, data=json.dumps(auth_payload), headers=self.headers)
                self.check_http_response_status(r)
                log.instance.logger.debug("Auth exchange success!")
            except:
                message = "Exception from request to auth. Going to retry 5 times. CurrentTry:" + str(retries)
                log.instance.logger.error(message, exc_info=True)
                retries+=1
                self.authenticate(username, apikey, auth_endpointurl, retries)
#
#Jonk
            try:
                dataset = r.json()
                self.token = dataset['access']['token']['id']
                log.instance.logger.debug('Access Token Id = ' + str(self.token))
                self.expiration = dataset['access']['token']['expires']
                log.instance.logger.debug('Access Token Expires = ' + str(self.expiration))
                self.tenant_id = dataset['access']['token']['tenant']['id']
                log.instance.logger.debug('Access Token Tenant Id = ' + str(self.tenant_id))
#                 set our headers with the token!
#                self.headers['X-Auth-Token'] = self.token
                self.service_catalog = dataset['access']['serviceCatalog']
                log.instance.logger.debug('Access ServiceCatalog = ' + str(self.service_catalog))
                self.rawobject = dataset
                self.status_code = r
                log.instance.logger.debug('Response Statuscode = ' + str(self.status_code))
            except KeyError:
                emsg="Could not aquire a dictionary object KeyError." + str(retries)
                log.instance.logger.error(message, exc_info=True)
                retries+=1
                self.authenticate(username, apikey, auth_endpointurl, retries)

    def get_token(self):
        return self.token
    
    def get_tenant_id(self):
        return self.tenant_id


    def get_endpoint(self, service, region):
        for item in self.service_catalog:
            if item['name'] == service:
                for endpoint in item['endpoints']:
                    try: # If region key exists...
                        if endpoint['region'] == region:
                            return endpoint['publicURL']
                    except KeyError: # Region support just isnt there.
                            return endpoint['publicURL']

    def check_http_response_status(self, result):
        if result.status_code == 200 or result.status_code == 203:
            pass
        else:
            emsg="AUTH status_code: " + str(result.status_code) + " Expected [200 or 203]"
            log.instance.logger.error(emsg, exc_info=True)
            raise AuthException(emsg)



class service:
    """Helper class to store all the various proper names of the various services"""
    clouddatabases = "cloudDatabases"
    cloudservers = "cloudServers"
    cloudfilescdn = "cloudFilesCDN"
    clouddns = "cloudDNS"
    cloudfiles = "cloudFiles"
    cloudloadbalancers= "cloudLoadBalancers"
    cloudmonitoring = "cloudMonitoring"
    cloudserversopenstack = "cloudServersOpenStack"

class region:
    dfw = "DFW"
    ord = "ORD"
    lon = "LON"

class identity:
    """ This is the coolest feature in the authentication library.
        I've done some database testing and storing this in a pickle serialized object file is
        by far the fastest in the land.
    """

    def __init__(self,region,isforce=None):
        __writtenby__ = 'Jon.Kelley@rackspace.com'

        if region == 'ord':      # B
            self.region = 'USA'  # A 
        elif region == 'dfw':    # N 
            self.region = 'USA'  # D   A
        elif region == 'lon':    #     I
            self.region = 'LON'  #     D


        if self.region == "LON":
             self.picklefile = AUTH_UK_PCKL_FILE
        else:
            self.picklefile = AUTH_US_PCKL_FILE

        
        log.instance.logger.info("COUNTRY_REGION="     + str(self.region))
        log.instance.logger.info("LOCAL_REGION="     + str(region))
        log.instance.logger.info("PICKLE_FILE_SELECTED=" + str(self.picklefile))

        if isforce: # If someone forces a new token, I presume we must oblige.
            self.remote() # Reload pickle to disk.
            log.instance.logger.info("Token force remote called by isforce option.")

    def tokenexpired(self, iso):
        """Takes ISO 8601 format(string) and converts into epoch time, then determines
            if the token has expired by comparing it to current epoch.
            Returns TRUE if it's expired.
            This was a nightmare.
        """

        auth_expire = dateutil.parser.parse(iso)    # Gets iso into datetime object.
        #self.logger.debug("Auth Expire_Timestamp: \t" + str(auth_expire))
        auth_expiry_epoch = time.mktime(auth_expire.timetuple())
        #self.logger.debug("Auth Expire_Epoch: \t" + str(auth_expiry_epoch))
        time_now_epoch    = time.time()
        #self.logger.debug("Time Current_Epoch: \t" + str(time_now_epoch))
        token_time_left = auth_expiry_epoch - time_now_epoch  # How much time is left?
        #self.logger.debug("Token time left: \t" + str(token_time_left))

        if token_time_left <= 1200: # Renew if expiring in 20 minutes.
            log.instance.logger.info("Fetching remote identity token. On-disk copy expired at " + str(str(auth_expire)))
            return True
        else:
            log.instance.logger.info("Identity token is valid (on-disk) Expires in " + str(round(token_time_left,0)) + "(seconds) exactly at " + str(auth_expire))
            return False

    def remote(self):
        """ Gets called only when we need to issue new external auth request and serialize it to disk. """
        auth     = RSAuth(self.region)
        authjson = auth.rawobject # json in
        
        try:
            file = open(self.picklefile, "w") # Open file aquisition lock, man
            pickle.dump(authjson, file) # Dump in pickle format
            file.close()
        except IOError:
            log.instance.logger.critical('Could not open pickle file.')
            raise AuthExceptionCritical('Could not open pickle file due to ioerror. Permissions maybe.')

    def getdict(self):
        """ Retrieves the cached auth object from disk. 
            If object token is expired, it re-retrieves.
        """
        if not os.path.isfile(self.picklefile):
            log.instance.logger.info("Auth.Identity Pickle file is missing: " + str(self.picklefile) + " -> I'm pinging IDENTITY to create this file.")
            self.remote()

        access = os.access(self.picklefile, os.W_OK)
        if access == True: # If file is readable...
            file = open(self.picklefile, 'rb') # Opens pickle from disk 
            try:
                mypickle = pickle.load(file)  # Loads pickle into dictionary
                file.close()
            except EOFError:
                print "==============================================================================="
                log.instance.logger.critical( "Pickle serialized obje is broke! Delete file \n" + str(file) )
                print "==============================================================================="

            try:
                expiration = mypickle['access']['token']['expires']
            except UnboundLocalError:
                print "==============================================================================="
                log.instance.logger.critical( "Can't decode token from file! Dont know why...  \n" + str(file) )
                print "==============================================================================="

            if self.tokenexpired(expiration):
                self.remote()
                self.getdict()

            return mypickle
        else:
            log.instance.logger.critical('Auth.Identity cannot read: ' + str(self.picklefile))
            raise AuthExceptionCritical('Auth.Identity cannot read: ' + str(self.picklefile))

    def get_token(self):
        """ Returns a str of your auth token """
        mypickle = self.getdict()
        return mypickle['access']['token']['id']

    def get_tenantid(self):
        """ Returns an int of your tenant id """
        mypickle = self.getdict()
        return int(mypickle['access']['token']['tenant']['id'])

    def get_expires(self):
        """ Returns a str of when token expires """
        mypickle = self.getdict()
        return mypickle['access']['token']['expires']

    def get_serviceCatalog(self):
        """ Returns the entire servicecatalog to you, for your own parsing I presume."""
        mypickle = self.getdict()
        return mypickle['access']['serviceCatalog']

    def get_info_token_expires_in(self):
        """ Returns the amount of seconds this tokens life still has."""
        mypickle = self.getdict()
        expires = mypickle['access']['token']['expires']
        expires = dateutil.parser.parse(expires)    # Gets iso into datetime object.
        auth_expiry_epoch = time.mktime(expires.timetuple())
        time_now_epoch    = time.time()
        seconds = auth_expiry_epoch - time_now_epoch  # How much time is left?
        return seconds

    def get_fullresponse(self):
        """ Returns the entire cached auth object so you can do your own work with the auth dictionary """
        mypickle = self.getdict()
        return mypickle

    def get_endpoint(self, service, region=None):
        """ Returns the endpoints from service catalog.
        Do not provide region arguement if the service has no region. """
        mypickle = self.get_serviceCatalog()
        for item in mypickle:
            if item['name'] == service:
                for endpoint in item['endpoints']:
                    try: # If region key exists...
                        if endpoint['region'] == region:
                            return endpoint['publicURL']
                    except KeyError: # Region support just isnt there.
                            return endpoint['publicURL']

    def get_endpoint_tenantid(self, service, region=None):
        """ Returns the endpoints from service catalog.
        Do not provide region arguement if the service has no region. """
        mypickle = self.get_serviceCatalog()
        for item in mypickle:
            if item['name'] == service:
                for endpoint in item['endpoints']:
                    try: # If region key exists...
                        if endpoint['region'] == region:
                            return endpoint['tenantId']
                    except KeyError: # Region support just isnt there.
                            return endpoint['tenantId']

    def get_json(self):
        """ Returns the entire cached auth object so you can do your own work with the auth dictionary """
        mypickle = self.getdict()
        myjson   = json.dumps(mypickle,sort_keys = False, indent = 3)
        return myjson

    #header = {}
    #header['X-Auth-Token'] = self.token
if __name__ == '__main__':

    """ Just an example of how to properly use this module.
        This module handles auth for you, and easily grabs the token, tenantid, or service endpoint for a particular service.
        
        Although if you call it as a module your code would look more like this:
            a = classauth.identity('USA')
            print a.get_token()
    """

    beforedemo = time.time()  # Sets up way to calculate demo time.
    auth  = identity('dfw')
    fast_token                          = auth.get_token()
    fast_tenantid                       = str(auth.get_tenantid())
    fast_expiration                     = auth.get_expires()
    fast_clouddns_endpoint              = auth.get_endpoint('cloudDNS') 
    fast_ord_clouddatabases_endpoint    = auth.get_endpoint('cloudDatabases','ORD')
    fast_ord_clouddatabases_tenantid    = auth.get_endpoint_tenantid('cloudDatabases','ORD')
    afterdemo = time.time() # Sets up way to calculate demo time.

    print "-----------------------------------------------------------------------------"
    print "Secret Auth Benchmark Easter Egg"
    print "This is what this library does to make auth fast as can be."
    print "\n"
    print "*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*"
    print "CACHED AUTH LIBRARY RESULT DEMONSTRATION:"
    print "*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*"

    print "Auth Token:\t\t"         + fast_token      # Auth token
    print "Auth Tenant:\t\t"        + fast_tenantid   # Tenant id
    print "Auth Expires:\t\t"       + fast_expiration # Expiration if you want it

    print "CloudDNS  Endpoint:\t"   + fast_clouddns_endpoint              # If the endpoint has no region (ie clouddns, cloudservers) leave off the second arg
    print "Databases Endpoint:\t"   + fast_ord_clouddatabases_endpoint    # If the endpoint has a region, define region as SECOND arg.
    print "Databases TenantID:\t"   +  fast_ord_clouddatabases_tenantid   # Grabs a products tenant ID.
    
    math = afterdemo - beforedemo
    print "\nTime taken (on-disk):\t " + str(math) + "(seconds)\n\n"



    beforedemo = time.time()  # Sets up way to calculate demo time.
    reAuth          = identity('dfw','force')
    slow_token      = reAuth.get_token()
    slow_expiration = reAuth.get_expires()
    afterdemo = time.time() # Sets up way to calculate demo time.

    print "*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*"
    print "DEMO OF FORCING A REMOTE TOKEN PULL."
    print "There are reasons to force a remote token pull, but there arent many. It's slow."
    print "*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*"
    print "Auth Token:\t"       + slow_token
    print "Auth Expires:\t\t"   + slow_expiration                       # Expiration if you want it

    math = afterdemo - beforedemo  
    print "\nTime taken (via internet)\t " + str(math) + "(seconds)\nSlllllllowwwwwwwwwwwwwwwwwwwwww\n"

