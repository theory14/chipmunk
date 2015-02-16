#!/usr/bin/env python

import urllib2
import urllib
import urlparse
import base64
import sys
import json

#------------------------------------------------------------------------------#
# Configuration data.
# This has the same sections, keys and values as in the chipmunkclient ini file
# except everything is converted to a nested dictionary.

config = {'Global': {
            'update_dns' : 'no'
        },
        'ChipmunkAPIServer': {
            'username' : 'user1',
            'password' : 'password1',
            'method' : 'set',
            'endpoint' : 'http://localhost:8080'
        },
        'dDNS': {
            'provider' : 'linode'
        },
        'linode' : {
            'api_key' : '311905cb27e82d67f4f6511f7f',
            'host' : 'myhouse',
            'domain' : 'cooldomain.com',
            'endpoint' : 'https://api.linode.com'
        }
    }

#------------------------------------------------------------------------------#

# maps a dynamic DNS provider name (used in the config file)
# to the name of the class that supports it)
DNS_PROVIDER_MAP = {'linode': 'LinodeDNS'}

class CMError(Exception):
    """
    Custom exception
    """
    pass

class ChipmunkRequest(object):
    # pylint:  disable=too-many-instance-attributes
    # This class uses these different attributes
    """
    Class to handle requests to the Chipmunk API server.
    """

    def __init__(self, config_dict):
        """
        Iinitialize

        Args:
            config_dict:  dictionary containing the following keys:
            username:  string for username on chipmunkapi server
            password:  string for password on chipmunkapi server
            server:  API endpoint URL
            method:  method to call on the endpoint

        """
        self.username = config_dict['username']
        self.password = config_dict['password']
        self.endpoint = config_dict['endpoint']
        self.method =  config_dict['method']
        # the return value from the server
        self.my_ip = None
        self.status = None
        # determin if we have a new IP address.  Initially set to true
        # since we don't know what our "old" address was when we start up.
        self.have_new_ip = True


    @property
    def method(self):
        return self._method
    @method.setter
    def method(self, value):
        if value == 'get':
            self._method = 'get/ip.json'
        elif value == 'set':
            self._method = 'set'
        else:
            raise ValueError()

    @property
    def endpoint(self):
        return self._endpoint
    @endpoint.setter
    def endpoint(self, value):
        try:
            # if the scheme is missing, assume it's http and try that
            parsed_url = urlparse.urlsplit(value, 'http')
        except AttributeError:
            print 'Invalid server URL.'
            sys.exit(1)
        if parsed_url.netloc == '':
            print 'Invalid server URL.'
            sys.exit(1)
        else:
            self._endpoint = urlparse.urlunsplit(parsed_url)

    def configure(self, config_dict):
        """
        comment
        """
        self.username = config_dict['username']
        self.password = config_dict['password']
        self.endpoint = config_dict['endpoint']
        self.method =  config_dict['method']

    def get_ip(self):
        """
        Get the client's IP address from the Chipmunk API Server.  The purpose
        of all of this is to discover the clients public IP address.  Depending
        on the sepcific method called, the API Server may do more than just
        return the client IP (see the API server for details).

        Returns:
            IP address as a string
        """
        # initially set ip to self.my_ip to put at a known good starting point
        ip = self.my_ip
        url = self.endpoint + '/' + self.method
        try:
            request = urllib2.Request(url)
            creds = base64.encodestring('%s:%s' % (self.username, self.password)).strip()
            request.add_header('Authorization', 'Basic %s' % creds)
            request.add_header('User-Agent', 'Chipmunk Client')
            result = urllib2.urlopen(request)
            answer = result.read()
            answer = json.loads(answer)
        except urllib2.HTTPError as e:
            message = 'Error connecting to Chipmunk API:  ' + str(e)
            raise CMError(message)
        except urllib2.URLError as e:
            message = 'Error connecting to Chipmunk API:  ' + str(e.reason)
            raise CMError(message)

        # catch if the response isn't json
        try:
            ip = answer['Client_IP']
        except ValueError as e:
            raise CMError(str(e))

        if self.method == 'set':
            self.status = answer['status']
        if ip == self.my_ip:
            self.have_new_ip = False
        else:
            self.have_new_ip = True
        # finally set the new ip as our ip
        self.my_ip = ip
        return self.my_ip

    @staticmethod
    def get_config_params(conf):
        """
        Setup the configuration parameters needed to communicate with the
        DNS provider and make updates.  This should be implimented for each
        sepcific DNS provider as the parameters for each are likely different.

        Args:
            configp_dict:  a ConfigParser.ConfigParser() object

        Returns:
            A dictionary with keys and values that are used by the provider
            specific implementation of this class.
        """
        settings = dict()
        try:
            settings['username'] = conf['ChipmunkAPIServer']['username']
            settings['password'] = conf['ChipmunkAPIServer']['password']
            settings['method'] = conf['ChipmunkAPIServer']['method']
            settings['endpoint'] = conf['ChipmunkAPIServer']['endpoint']
        except KeyError as e:
            print >> sys.stderr, 'Missing config option.'
            print >> sys.stderr, '\t' + str(e)
            sys.exit(1)
        return settings

class DNSProvider(object):
    """
    Abstract class for implimenting the ability to update
    DNS providers.
    """
    def __init__(self):
        raise NotImplementedError

    def update_dns(self):
        """
        Make update to DNS entry

        Should raise CMError() exceptions for problems with the connection or
        data.  The calling routine should handle this error appropriately.

        Returns:
            String suitable for display to end user indicating status of
            the update
        """
        raise NotImplementedError

    def configure(self, config_data):
        """
        Read a the values from a dictionary and set the appropriate variables.

        Args:
            config_data:  dictionary whose key:value pairs are used to
            set the appropriate variables
        """
        raise NotImplementedError

    @staticmethod
    def get_config_params(configp_dict):
        """
        Setup the configuration parameters needed to communicate with the
        DNS provider and make updates.  This should be implimented for each
        sepcific DNS provider as the parameters for each are likely different.

        Args:
            configp_dict:  a ConfigParser.ConfigParser() object

        Returns:
            A dictionary with keys and values that are used by the provider
            specific implementation of this class.
        """
        raise NotImplementedError

class LinodeDNS(DNSProvider):
    """
    Impliment Linode DNS update

    For details of the API see: https://www.linode.com/api
    """
    def __init__(self):
        self.api_key = ''
        self.domain = ''
        self.host = ''
        self.endpoint = 'https://api.linode.com'
        self.domain_id = None
        self.resource_id = None
        self.linode_ip = None

    def configure(self, config_data):
        """
        see super class
        """
        try:
            self.api_key = config_data['api_key']
            self.domain = config_data['domain']
            self.host = config_data['host']
            self.endpoint = config_data['endpoint']
            self.api_key = config_data['api_key']
        except KeyError as e:
            print >> sys.stderr, 'Missing config option.'
            print >> sys.stderr, '\t' + str(e)
            sys.exit(1)

    def update_dns(self, new_ip_addr):
        """
        Perform DNS update.

        Any connection errors are raised as CMError() exceptions.  These
        should be handled appropriately when ths method is called.

        Args:
            new_ip_addr:  string with the new IP address to set
        """
        self.domain_id = self._get_domain_id()
        self.resource_id = self._get_resource_id()
        self.linode_ip = self._get_linode_ip()
        if new_ip_addr != self.linode_ip:
            self._set_linode_ip(new_ip_addr)
            return 'Success'
        else:
            return 'No Update Needed'

    def _get_domain_id(self):
        """
        Get the DomainID for the given domain.
        https://www.linode.com/api/dns/domain.list

        Returns:  DomainID of domain
        """
        if self.domain_id:
            return self.domain_id
        method = {'api_action': 'domain.list'}
        data = self._make_api_call(method)
        for entry in data:
            if entry['DOMAIN'] == self.domain:
                return entry['DOMAINID']


    def _get_resource_id(self):
        """
        Get the ResourceID of the entry for the given host.
        https://www.linode.com/api/dns/domain.list

        Returns:  ResourceID for the host
        """
        if self.resource_id:
            return self.resource_id
        method = {'api_action' : 'domain.resource.list',
                   'DomainID' : self.domain_id}
        data = self._make_api_call(method)
        for entry in data:
            if entry['NAME'] == self.host:
                return entry['RESOURCEID']


    def _get_linode_ip(self):
        """
        Get the current IP address set in Linode's DNS.
        https://www.linode.com/api/dns/domain.resource.list

        Returns: IP address (as a stirng) matching the hostname
        """
        method = {'api_action' : 'domain.resource.list',
                   'DomainID' : self.domain_id}
        data = self._make_api_call(method)
        for entry in data:
            if entry['NAME'] == self.host:
                return entry['TARGET']


    def _set_linode_ip(self, new_ip):
        """
        Set the IP address Linode DNS.
        https://www.linode.com/api/dns/domain.resource.update

        Returns:  ResouceID that was updated
        """
        method = {'api_action': 'domain.resource.update',
                  'ResourceID' : self.resource_id,
                  'DomainID' : self.domain_id,
                  'Target': new_ip}
        data = self._make_api_call(method)
        return data['ResourceID']

    def _make_api_call(self, query_dict):
        """
        Make the actual API call to Linode.

        Args:
            query_dict:  Dictionary containing the API methods and parameters.
                         This is converted into a URL query string

        Returns:  Data dictionary from linode API call.
        """
        method = urllib.urlencode(query_dict)
        url = self.endpoint + '/?api_key=' + self.api_key + '&' + method
        answer = None
        try:
            request = urllib2.Request(url)
            result = urllib2.urlopen(request)
            answer = result.read()
        except urllib2.HTTPError as e:
            raise CMError('Error connecting to DNS provider: %s' % str(e))
        except urllib2.URLError as e:
            raise CMError('Error connecting to DNS provider: %s' % str(e.reason))

        try:
            answer = json.loads(answer)
        except ValueError as e:
            raise CMError('Error decoding JSON repsone:  %s' % str(e))

        if answer:
            if len(answer['ERRORARRAY']) != 0:
                message = (answer['ERRORARRAY']['ERRORMESSAGE'])
                raise CMError('Problem with DNS Update API call:  %s' % str(message))
            else:
                return answer['DATA']


    @staticmethod
    def get_config_params(configp_dict):
        """
        See superclass
        """
        retval = dict()
        try:
            retval['api_key'] = configp_dict['linode']['api_key']
            retval['host'] = configp_dict['linode']['host']
            retval['domain'] = configp_dict['linode']['domain']
            retval['endpoint'] = configp_dict['linode']['endpoint']
        except KeyError as e:
            print >> sys.stderr, 'Missing config option.'
            print >> sys.stderr, '\t' + str(e)
            sys.exit(1)
        return retval

class Config(object):
    """
    Process configuration data
    """
    def __init__(self):
        self.update_dns = False
        # params needed for CM API Server
        self.cmapi = None
        # params needed for DNS updates.  The contents will vary by
        # provider
        self.dns_provider = None
        self.dns_params = dict()

    def _global_config(self, conf):
        """
        setup the global config file options
        """
        update_dns = conf['Global']['update_dns']

        # update_dns
        if update_dns.lower() == 'yes':
            self.update_dns = True
        else:
            self.update_dns = False


    def configure(self, conf):
        """
        Read configuration file for parameters and set up everything.

        Args:
            config_file:  config file to read
        """
        # get global settings
        self._global_config(conf)
        # parameters for interacting with chipmunk API server
        self.cmapi = ChipmunkRequest.get_config_params(conf)
        # fill in appropriate dns provider values
        if self.update_dns:
            self.dns_provider = conf['dDNS']['provider']
            self.dns_params = globals()[DNS_PROVIDER_MAP[self.dns_provider]].get_config_params(conf)


def single_run(conf):
    """
    Run everything one time.  Allows a command line one line update or
    incorporation into a shell script.  Prints status messages to stdout.
    """

    cm = ChipmunkRequest(conf.cmapi)
    try:
        ip = cm.get_ip()
    except CMError as e:
        print >> sys.stderr, 'Problem getting IP address:  %s' % str(e)
        sys.exit(1)
    print 'IP:  %s' % (cm.my_ip)
    if cm.status:
        print 'Status:  %s' % (cm.status)
    if conf.update_dns:
        dnupdate = globals()[DNS_PROVIDER_MAP[conf.dns_provider]]()
        dnupdate.configure(conf.dns_params)
        try:
            update_result = dnupdate.update_dns(cm.my_ip)
        except CMError as e:
            print >> sys.stderr, 'Problem updating DNS:  %s' % str(e)
            sys.exit(1)
        print 'DNS Update status:  %s' % (update_result)
    sys.exit(0)


def main():
    """
    main
    """
    conf = Config()
    conf.configure(config)
    single_run(conf)


if __name__ == '__main__':
    main()

