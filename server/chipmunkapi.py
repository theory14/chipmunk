"""
API server that provides various services for my Dynamic IP address
solution.
"""

import bottle
import cmcommon
import sys

# default config file
CONFIG_FILE = 'chipmunkapi.ini'

try:
    conf = cmcommon.Config(CONFIG_FILE)
except IOError as e:
    print e
    sys.exit(1)


#
# check Basic Auth
#

def auth_check(username, password):
    """
    Check users against the user_data.
    """
    if username in conf.users:
        if password == conf.users[username]:
            return True
    return False


#
# api paths
#

@bottle.get('/')
def bugger_off():
    """
    Nothing available on /
    """
    return bottle.template('move_along.tpl')

@bottle.get('/get/ip')
@bottle.auth_basic(auth_check)
def show_ip():
    """
    Return the requestor's IP.

    Returns:
        string with "Your IP:  IPADDR"
    """
    ip = bottle.request.remote_addr
    return bottle.template("Your IP: {{ip}}", ip=ip)

@bottle.get('/get/ip.json')
@bottle.auth_basic(auth_check, realm='chipmunk')
def show_ip_json():
    """
    Return the requestor's IP in a JSON object.

    Returns:
        json object of the form "{'Client_IP': IPADDR}"
    """
    ip = bottle.request.remote_addr
    retval = {'Client_IP': ip}
    return retval

@bottle.get('/set')
@bottle.auth_basic(auth_check, realm='chipmunk')
def set():
    """
    Set the user's address in a persistent file that can
    later be consumed by other utilities.  This allows asynchronous
    messaging of the client's address.

    Returns:
        - data saved per ClientData.persist_info()
        - JSON object with client IP and status of the form:
             {'Client_IP': IPADDR,
              'status': status}
    """
    ip = bottle.request.remote_addr
    user = bottle.request.auth[0]
    status = 'incomplete'
    access_saver = cmcommon.ClientData(conf)
    try:
        access_saver.persist_info(user, ip)
        status = 'saved'
    except IOError as e:
        status = 'failed'
        bottle.abort(500, 'Failed to persist information.')
    retval = {'Client_IP': ip,
              'status': status}
    return retval

#
# static files
#

@bottle.get('/img/<filename:re:.*\.(jpg|gif|png)>')
def images(filename):
    """
    Serve static files from the img directory.
    """
    return bottle.static_file(filename, root='img')

#
# custom errors
#

@bottle.error(404)
def error_404(error):
    """
    Custom 404 error response.
    """
    return bottle.template('move_along.tpl')


if __name__ == '__main__':
    # Run the development server if this script is called directly.
    bottle.run(host='0.0.0.0', port=8080, debug=True)
