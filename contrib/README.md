# Contrib

Various scripts and tools to help out with using Chipmunk

# [OpenBSD](http://www.openbsd.org) [rc.d(8)](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man8/rc.d.8?query=rc%2ed) Script

`contrib/openbsd-rc.d-chipmunkclient` is a rc.d script for OpenBSD to allow
control of the chipmunkclient from the rc.d subsystem.

To use the script:
- Copy `client/chipmunkclient.py` to `/usr/local/sbin/chipmunkclient`.  Ensure
that the script is executable
- Copy `client/chipmunkclinet.ini` to `/usr/local/etc/chipmunkclient.ini`.
Check the ownership and permissions are set so as to not allow disclosure of the
credentials stored in the file (e.g., root:wheel and mode 600)
- Copy `contrib/openbsd-rc.d-chipmunkclient` to `/etc/rc.d/chipmunk`
- Add `chipmunk` to the `pkg_scripts` variable in `/etc/rc.conf.local`
