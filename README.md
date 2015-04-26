# Chipmunk

Chipmunk is composed of a couple of components and provides several different
functions.  At a high level, it provides the ability to discover your public IP
address and update DNS with that address -- not unlike what you can do with
various Dynamic DNS providers and scripts such as
[ddclient](http://sourceforge.net/p/ddclient/wiki/Home/).

There are two components of Chipmunk.  Though designed to be used together,
they are independent.
- Server:  Returns the IP address of the client making the request.  Additionally,
can persist the address to disk for other uses
- Client:  Connects to the server to discover its public IP address.  If desired,
it can update a DNS provider with information.  Can be run either as a one shot
CLI program or as a daemon.

# Dependencies

## Server
- The [bottle](http://bottlepy.org) python framework.  This could be installed
system wide or simply dropped in the application directory with the rest of the
chipmunk server.
- At least python2.6
- Since username/password credentials are used for all connections, it is
highly recommended to use TLS encryption on your web server (HTTPS)

## Client
- Only tested with python2.7 (It would be great to get reports of other versions
it works with and fixes to work with more versions.)

# Server

The server is a simple WSGI program created with [bottle](http://bottlepy.org).
- `chipmunkapi.py` is the main server application
- `cmcommon.py` contains additional classes and functions used by the
application.
- `chipmunkapi.wsgi` is a WSGI script to allow launching/running of the bottle
application
- `chipmunkapi.ini` is the configuration file for the server.

Included for conveneince are:
- `chipmunk.vhost.sample` is an Apache virtual host.  Most likely you'll need
to modify this to suite your environment.

## Installation

There are many different ways to configure WSGI applications for different
web servers.  The exact details of how to do this will depend on your
environment and what you have running.

### Apache

- Install mod_wsgi that matches your python version (at least python2.6 is
needed)
- Setup a directory for the application and copy the contents of the `server/`
directory there
- Edit the config file `chipmunkapi.ini` as appropriate for your environment
and uses.
    - You'll need to create a directory for `client_update_dir` and enter that
    in that path in the config file.
- Setup a virtual host (or modify your apache config) to run the application
using `chipmunk.vhost.sample` as a guide.  It may be sufficent to simply change
the paths in the sample vhost file and use that.
- Reload Apache to start the application.

## Configuration

See the comments in `chipmunkapi.ini` for configuration.

## API

### Authentication

Authentication is just HTTP Basic authentication.  An authentication header
must be passed with all requests.  Usernames and passwords are configured on
in `chipmunkapi.ini` on the server side.

### Methods

The following methods exist:

- `/get/ip`: Returns a text string in the form of `Your IP:  IPADDR` where
IPADDR is the requesting clients IP Address
- `/get/ip.json`:  Returns a JSON object of the form `{'Client_IP': IPADDR}`
where IPADDR is the requesting clients IP Address
- `/set`:  The set method does two things:
    - Persists the clients information on the server.  The address is stored in
    a file named `username.cm` where the username is the username used for
    authentication.  The file simply contains the client's IP address.
    - Returns a JSON object of the form `{'Client_IP': IPADDR,
    'status': status}` where IPADDR is the requesting clients IP Address and
    status is the status of persisting the data on the server.

# Client

The client, `chipmunkclient.py` can run in either a single shot mode from the
command line (or however else you want to call it) or fork itself into the
background and run as a deamon.  In either case, a config file must be
specified and the appropriate sections of the file setup.  The included
`sample-cmclient.ini` is commented with the details of how to configure
the client.

If you are conencting over HTTPS, certificates are not validated.  This is the
standard behvior in python < 2.7.9.  In 2.7.9, this was changed to default to
validating certs.  Though this is a good thing, the chipmunk client simply
mirrors the non-validating behavior.  This needs to be made into a config
option.

## DNS Update Support

If `update_dns` is set in the `[Global]` section, then a DNS provider will be
updated with the new address.  The particular provider is specificed in the
`[dDNS]` section's `provider` option.

Currently only [Linode](http://www.linode.com) DNS is supported.  Additional
providers can be supported by subclassing the DNSProvider() class and providing
all of the required methods.

## Daemon

### Log Rotation

When run as a daemon, sending a SIGUSR1 signal will cause the client to close
the current log file and re-open it.  The typical way this would be used is to:

1.  Move the current open log file to a new name
2.  Send SIGUSR1 to the the daemon

Note that this is consistent with the newsyslog facility found in most BSD
derived platforms.

## Configuration File Reload

The configuration file can be reloaded while the daemon is running by
sending a SIGHUP.




