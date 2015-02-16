# chipmunkista

A version of the Chipmunk Client made to run from
[Pythonista](http://omz-software.com/pythonista/).  The primary differences
between this version and the standard client are:
- No daemon mode.  Runs only as a single-shot.
- No logging.
- Configuration is as a dictionary named "config" at the beginning of the
script instead of an external config file.

# Configuration

As mentioned above, the configuration data is contained directly in the
script instead of an external ini file.  The sections, keys and values are all
the same as in the chipmunkclient ini file with the exception that the data
is stored in nested dictionaries instead of in ini format.  You will need to
edit this dictionary for your particular situation.
