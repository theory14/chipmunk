#!/usr/bin/env python

import urllib2
import urllib
import urlparse
import base64
import argparse
import sys
import json
import ConfigParser
import os
import time
import atexit
import signal
import logging

# maps a dynamic DNS provider name (used in the config file)
# to the name of the class that supports it)
DNS_PROVIDER_MAP = {'linode': 'LinodeDNS'}

# This class from
# http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
class Daemon(object):
    """
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        # si = file(self.stdin, 'r')
        # so = file(self.stdout, 'a+')
        # se = file(self.stderr, 'a+', 0)
        # os.dup2(si.fileno(), sys.stdin.fileno())
        # os.dup2(so.fileno(), sys.stdout.fileno())
        # os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
       # Check for a pidfile to see if the daemon already runs
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError as e:
            pid = None

        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % self.pidfile)
            return # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """

class Logger(object):
    """
    Wrapper around logging

    Supported levels:
        - info
        - warning
        - error

    """
    def __init__(self, filename):
        """
        Create logger

        Args:
            filename:  name of the log file
        """
        self.logfile = os.path.abspath(filename)
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger('littled')
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        try:
            handler = logging.FileHandler(self.logfile)
        except IOError as e:
            sys.exit(1)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def rotate_handler(self):
        self.log('info', 'Rotating logs.')
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)
        self.logger = self._setup_logger()
        self.log('info', 'New log file started.')

    def log(self, level, message):
        if  self.logger:
            if level == 'info':
                self.logger.info(message)
            elif level == 'warning':
                self.logger.warning(message)
            elif level == 'error':
                self.logger.error(message)

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

    def get_ip(self):
        """
        Get the client's IP address from the Chipmunk API Server.  The purpose
        of all of this is to discover the clients public IP address.  Depending
        on the sepcific method called, the API Server may do more than just
        return the client IP (see the API server for details).

        Returns:
            IP address as a string
        """
        url = self.endpoint + '/' + self.method
        try:
            request = urllib2.Request(url)
            creds = base64.encodestring('%s:%s' % (self.username, self.password)).strip()
            request.add_header('Authorization', 'Basic %s' % creds)
            request.add_header('User-Agent', 'Chipmunk Client')
            result = urllib2.urlopen(request)
            answer = result.read()
        except urllib2.HTTPError as e:
            print >> sys.stderr, 'Error connecting to Chipmunk API:  ' + str(e)
            sys.exit(1)
        except urllib2.URLError as e:
            print >> sys.stderr, 'Error connecting to Chipmunk API:  ' + str(e.reason)
            sys.exit(1)
        answer = json.loads(answer)
        self.my_ip = answer['Client_IP']
        if self.method == 'set':
            self.status = answer['status']
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
            settings['username'] = conf.get('ChipmunkAPIServer', 'username')
            settings['password'] = conf.get('ChipmunkAPIServer', 'password')
            settings['method'] = conf.get('ChipmunkAPIServer', 'method')
            settings['endpoint'] = conf.get('ChipmunkAPIServer', 'endpoint')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            print >> sys.stderr, 'Problem with your configuration file.'
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

class ChipmunkDNSUpdateError(Exception):
    """
    Custom Exception for errors in updating Dynamic DNS.
    """
    pass

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
        self.api_key = config_data['api_key']
        self.domain = config_data['domain']
        self.host = config_data['host']
        self.endpoint = config_data['endpoint']
        self.api_key = config_data['api_key']

    def update_dns(self, new_ip_addr):
        """
        Perform DNS update.

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
        try:
            request = urllib2.Request(url)
            result = urllib2.urlopen(request)
            answer = result.read()
            answer = json.loads(answer)
        except urllib2.HTTPError as e:
            print e
        except urllib2.URLError as e:
            print e.reason
        if len(answer['ERRORARRAY']) != 0:
            raise ChipmunkDNSUpdateError(answer['ERRORARRAY']['ERRORMESSAGE'])
        else:
            return answer['DATA']

    @staticmethod
    def get_config_params(configp_dict):
        """
        See superclass
        """
        retval = dict()
        try:
            retval['api_key'] = configp_dict.get('linode', 'api_key')
            retval['host'] = configp_dict.get('linode', 'host')
            retval['domain'] = configp_dict.get('linode', 'domain')
            retval['endpoint'] = configp_dict.get('linode', 'endpoint')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            print >> sys.stderr, 'Problem with your configuration file.'
            print >> sys.stderr, '\t' + str(e)
            sys.exit(1)
        return retval

class Config(object):
    """
    Process configuration data
    """
    def __init__(self):
        self.config_file = None
        # general settings
        self.update_dns = False
        self.daemonize = False
        # params needed for CM API Server
        self.cmapi = None
        # params needed for DNS updates.  The contents will vary by
        # provider
        self.dns_provider = None
        self.dns_params = dict()
        self.daemon = dict()

    def _global_config(self, conf):
        """
        setup the global config file options
        """
        try:
            update_dns = conf.get('Global', 'update_dns')
            daemonize = conf.get('Global', 'daemonize')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            print >> sys.stderr, 'Problem with your configuration file.'
            print >> sys.stderr, '\t' + str(e)
            sys.exit(1)

        # update_dns
        if update_dns.lower() == 'yes':
            self.update_dns = True
        else:
            self.update_dns = False
        # daemonize
        if daemonize.lower() == 'yes':
            self.daemonize = True
        else:
            self.daemonize = False

    def configure(self, config_file):
        """
        Read configuration file for parameters and set up everything.

        Args:
            config_file:  config file to read
        """
        self.config_file = os.path.abspath(config_file)
        conf = ConfigParser.ConfigParser()
        conf.read(config_file)
        # get global settings
        self._global_config(conf)
        # parameters for interacting with chipmunk API server
        self.cmapi = ChipmunkRequest.get_config_params(conf)
        # fill in appropriate dns provider values
        if self.update_dns:
            self.dns_provider = conf.get('dDNS', 'provider')
            self.dns_params = globals()[DNS_PROVIDER_MAP[self.dns_provider]].get_config_params(conf)
        # deamon parameters if we are going to be a daemon
        if self.daemonize:
            self.daemon['interval'] = conf.get('Daemon', 'interval')
            self.daemon['pidfile'] = conf.get('Daemon', 'pidfile').strip("'").strip('"')
            self.daemon['logfile'] = conf.get('Daemon', 'logfile').strip("'").strip('"')

class CMDaemon(Daemon):
    """
    Implimentation of Daemon class.  Allows this to be run as a deamon.
    """

    def __init__(self, conf):
        """
        Setup the daemon version of things

        Args:
            conf:  a Config object with everything initialized
        """
        self.conf = conf
        super(CMDaemon, self).__init__(self.conf.daemon['pidfile'])
        self.logger = Logger(self.conf.daemon['logfile'])
        # register a handler for SIGHUP to re-load the configuration
        signal.signal(signal.SIGHUP, self._sighup_handler)
        # cleanly die
        signal.signal(signal.SIGTERM, self._sigterm_handler)
        signal.signal(signal.SIGUSR1, self._sigusr1_handler)

    def _sighup_handler(self, signum, frame):
        """
        Handle a SIGHUP by reloading the config.
        """
        self.logger.log('info', 'Reloading Configuration.')
        self.conf.configure(self.conf.config_file)

    def _sigusr1_handler(self, signum, frame):
        """
        Handle SIGUSR1 to allow log file rotation.
        """
        self.logger.rotate_handler()

    def _sigterm_handler(self, signum, frame):
        self.logger.log('info', 'Exiting.')
        sys.exit(0)

    def run(self):
        """
        Implement the run method to allow daemonization.  Execute all
        logic in here.
        """
        self.logger.log('info', 'Starting.')
        cm = ChipmunkRequest(self.conf.cmapi)
        if self.conf.update_dns:
                dnupdate = globals()[DNS_PROVIDER_MAP[self.conf.dns_provider]]()
                dnupdate.configure(self.conf.dns_params)

        while True:
            cm.get_ip()
            self.logger.log('info', 'Current IP is: %s ' % cm.my_ip)
            if self.conf.update_dns:
                message = dnupdate.update_dns(cm.my_ip)
                self.logger.log('info', 'DNS Update Status:  %s' % message)
            # sleep for a period of time before checking again.
            time.sleep(int(self.conf.daemon['interval']))

def single_run(conf):
    """
    Run everything one time.  Allows a command line one line update or
    incorporation into a shell script.  Prints status messages to stdout.
    """

    cm = ChipmunkRequest(conf.cmapi)
    ip = cm.get_ip()
    print 'IP:  %s' % (cm.my_ip)
    if cm.status:
        print 'Status:  %s' % (cm.status)
    if conf.update_dns:
        dnupdate = globals()[DNS_PROVIDER_MAP[conf.dns_provider]]()
        dnupdate.configure(conf.dns_params)
        update_result = dnupdate.update_dns(cm.my_ip)
        print 'DNS Update status:  %s' % (update_result)
    sys.exit(0)

def _get_args():
    """
    Get command line arguments.

    Returns:  argparse Namespace
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c',
                        '--config',
                        required=True,
                        help='Configuration File')
    args = parser.parse_args()
    return args

def main():
    """
    main
    """
    args = _get_args()
    # load configuration data
    conf = Config()
    conf.configure(args.config)

    if conf.daemonize:
        daemon = CMDaemon(conf)
        daemon.start()
    else:
        single_run(conf)


if __name__ == '__main__':
    main()

