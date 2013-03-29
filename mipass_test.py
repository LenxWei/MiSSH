#!/usr/bin/env python

'''Unittest for mipass.

.. moduleauthor:: Lenx Wei <lenx.wei@gmail.com>
'''

import os
import time 
import sys
import mipass
        
def usage():
    print """Test usage:
mipass [opt] [id]
   -d      front daemon mode
   -s pass set pass
   -m pass set master pass
   -k      kill the master daemon process
   -v      verbose mode
"""

def test():
    global verbose
    
    import getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dhs:m:kv")
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
        elif o == '-k':
            kill = True
        elif o == '-d':
            front_server = True
        elif o == '-v':
            mipass.verbose=True # why do I need to assign twice ?!
        else:
            print "unhandled option:", o,a
            usage()
            sys.exit(2)
    
    c = mipass.client(mipass.unixsock)

    # check whether the service is started
    if(front_server):
        c.kill()
        
        try:
            os.remove(mipass.unixsock)
        except:
            pass

        print "The password keeping service starts..."
        mipass.start_service(mipass.unixsock)
        return
    
    if kill:
        c.kill()
        return
        
    c.connect()

    if c.need_master()==-2:
        import getpass
        while 1:
            master_pwd = getpass.getpass("create the master password:")
            master_pwd2 = getpass.getpass("please repeat it:")
            if master_pwd == master_pwd2:
                break
            print "They are not matched!"
        ok, resp = c.set_master(master_pwd)
        if not ok:
            print "Can't set the master key. Error:",resp
            sys.exit(1)
            
    elif c.need_master()== -1:
        import getpass
        while 1:
            master_pwd = getpass.getpass("input the master password:")
            ok, resp = c.check_master(master_pwd)
            print ok, resp
            if not ok:
                print "Please try again. Error:",resp
            else:
                break
        
    # set/put master pass
    if master != None:
        ok, resp = c.set_master(master)
        print ok, resp
    
    if id != None:
        if setting:
            ok, resp = c.set_pass(id, password)
        else:
            ok, resp = c.get_pass(id)
        print ok, resp
        
    c.close()

if __name__ == "__main__":
    test()
    
