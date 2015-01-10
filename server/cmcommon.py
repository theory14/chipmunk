import ConfigParser
import os
import sys

class Config(object):
    """
    Configuration data for chipmunk API server and associated
    utility functions.
    """

    def __init__(self, conf_file=None):
        """
        Initialize.  If a configuration file is passed, its contents
        will be used to setup everything.
        """
        # usernames and passwords
        self.users = {}
        # where  client info is written
        self.client_update_dir = '/tmp'

        if conf_file:
            self.configure(conf_file)

    def configure(self, config_file):
        """
        Read, parse and load config file.

        Args:
            config_file:  name of the config file to read
        """
        conf = ConfigParser.ConfigParser()
        conf.read(config_file)

        # setup users and their passwords
        for user in conf.options('Users'):
            self.users[user] = conf.get('Users', user)

        # set client_update_dir
        self.client_update_dir = conf.get('Paths', 'client_update_dir')


    @property
    def client_update_dir(self):
        return self._client_update_dir
    @client_update_dir.setter
    def client_update_dir(self, value):
        if os.path.isdir(value):
            self._client_update_dir = value
        else:
            raise IOError('client_update_directory does not exist.')
            sys.exit(1)


class ClientData(object):
    """
    Class to support persisting client data from the /set method call.
    """

    def __init__(self, config):
        # where to write stuff
        self.dest_dir = config.client_update_dir

    def persist_info(self, user, ip):
        """
        Write IP address info to a file named <user>.cm

        Args:
            user:  username
            ip:  client's IP
        """
        filename = self.dest_dir + '/' + user + '.cm'
        fh = open(filename, 'w')
        fh.write(ip)
        fh.write('\n')
        fh.close()



