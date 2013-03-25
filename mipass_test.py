'''Unittest for mipass.

.. moduleauthor:: Lenx Wei <lenx.wei@gmail.com>
'''

import os
import time 
import sys
from mipass import *

def usage():
    print """Test usage:
mipass [opt] [id]
   -d      front daemon mode
   -s pass set pass
   -M pass set master pass
   -m pass master pass
   -k      kill the master daemon process
"""

def test():
    import getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dhs:m:M:k")
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    id = None
    if len(args) > 0:
        id = args[0]
        
    # secure_replace_file(conf_fn, conf_fn+".new")
    setting = False
    password = None
    setting_master = False
    master = None
    kill = False
    front_server = False
    
    for o, a in opts:
        if o == "-h":
            usage()
            sys.exit()
        elif o == "-s":
            setting = True
            password = a
        elif o == "-m":
            master = a
        elif o == '-M':
            master = a
            setting_master = True
        elif o == '-k':
            kill = True
        elif o == '-d':
            front_server = True
        else:
            assert False, "unhandled option"
    
    # check whether the service is started
    if(front_server):
        try:
            os.remove(unixsock)
        except:
            pass

        start_service(unixsock)
        return
    
    c = client(unixsock)
    c.connect()
    if not c.connected:
        if kill:
            sys.exit(0)
        try:
            os.remove(unixsock)
        except:
            pass
        try:
            start_service_daemon(unixsock)
        except:
            pass
        c.connect()
    if not c.connected:
        print "can't start service"
        sys.exit(1)
    if kill:
        c.kill()
        sys.exit(0)
    # set/put master pass
    if master != None:
        if setting_master:
            c.set_master(master)
        else:
            c.check_master(master)
    
    if id != None:
        if setting:
            c.set_pass(id, password)
        else:
            c.get_pass(id)
        
    # set/get pass
    
    # close
    c.close()

if __name__ == "__main__":
    test()
    
