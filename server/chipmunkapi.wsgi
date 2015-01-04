import os
import sys
import bottle

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path = [os.getcwd()] + sys.path


import chipmunkapi
application = bottle.default_app()
