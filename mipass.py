# a server provides password cache and lookup service

# password format:
# id_md5_hashed_and_hex = seq,pass_aes_encrypted_by_second_key_and_hex
# hex: binascii.b2a_hex(s)
# seq is used to generate the IV, sha256 using the second key

# master key:
# master = maseter_key_md5_hash_and_hex
# second = seq,second_key_aes_encrypted_by_master_key_and_hex
#   the second key is (a 240bit-long random string, plus its least 16bit of crc32) 
#   and it should be changed when the master key is changed.
#   Crypto.Random.get_random_bytes(30)
#   binascii.crc32(str) & 0xffff
#   seq is used to generate the IV, sha256 using the master key

import Crypto
from binascii import b2a_hex, a2b_hex

import socket
import threading
import SocketServer
import os
import time 
import sys

null_str = '\n'

conf_fn = "~/.missh"
conf_fn = os.path.expanduser(conf_fn)

unixsock = "~/.missh.sock"
unixsock = os.path.expanduser(unixsock)

# utility functions

def remove_remark(line):
    pos = line.find("#")
    if(pos > 0):
        line = line[:pos]
    line = line.strip()
    return line

def get_key_val(line):
    pos = line.find("=")
    if(pos < 0):
        return "", ""
    return line[:pos].strip().lower(), line[pos + 1:].strip()
    
def secure_replace_file(old_fn, new_fn):
    back_fn = old_fn + ".old"
    try:
        os.remove(back_fn)
    except:
        pass

    try:
        # mov old_fn to back_fn
        os.rename(old_fn, back_fn)
        # mov new_fn to old_fn
        os.rename(new_fn, old_fn)
    except:
        print "Error: can't replace %s!" % old_fn
        return
        
    # write rubbish to back_fn
    # flush
    # delete back_fn
    try:
        f = open(back_fn, 'r+b')
        f.seek(0, os.SEEK_END)
        length = f.tell()
        f.seek(0, os.SEEK_SET)
        rub = 'F' * 63 + '\n'
        for i in xrange(0, length / 64 + 1):
            f.write(rub)
        f.flush()
        os.fsync(f.fileno())
        f.close()
        os.remove(back_fn)
    except:
        print "Error: can't delete the old conf file at %s" % back_fn

def get_header(s):
    pos = s.find(' ')
    if(pos > 0):
        return s[:pos].strip().lower(), s[pos + 1:].strip()
    return s.strip().lower(), ''
    
# encrypt/decrypt
def mi_decrypt(seq, enc, key):
    # [todo]
    return enc 
    pass

def mi_encrypt(seq, plain, key):
    # [todo]
    return plain 
    pass

def get_seq(s):
    p = s.find(",")
    if(p > 0):
        return int(s[:p]), s[p + 1:]
    else:
        return 0, s[p + 1:]
    
# configuration file
class pass_db:
    fn = null_str
    master_hash = null_str
    second_enc = null_str
    password = {}  # id:pass, as in file
    max_seq = 0  # for IV
    timeout = 120  # in min
    init_ok = False
    
    def __init__(self, fn):
        self.fn = fn
        self.init_ok = False
        self.read_cfg()
        
    def read_cfg(self):
        line_cnt = 0
        try:
            f = open(self.fn)
            for line in f:
                line_cnt = line_cnt + 1
                
                # strip and remove remarks
                line = remove_remark(line)
                if line == '':
                    continue
                
                # fetch the key and value
                try:
                    key, val = get_key_val(line)
                    if(key == "master"):
                        self.master_hash = mi_decrypt(val)
                    elif(key == "second"):
                        self.second_enc = val
                    elif(key == "timeout"):
                        self.timeout = int(val)
                    elif(key == ""):
                        raise "no key"
                    else:
                        self.password[key] = val
                except:
                    print "error config line #%d : %s" % (line_cnt, line)
                    continue
            
            self.init_ok = True
            f.close() 
        except:
            print "bad configuration file:", self.fn
            return
        
    def write_cfg(self):
        new_fn = self.fn + ".new"
        # write to new_fn
        try:
            f = open(new_fn, 'wb')
            f.write("master = %s\n" % b2a_hex(self.master_hash))
            f.write("second = %s\n" % b2a_hex(self.second_enc))
            f.write("timeout = %d\n" % self.timeout)
            f.write("\n")
            for i in self.password:
                f.write("%s = %s\n" % (b2a_hex(i), b2a_hex(self.password[i])))
            f.flush()
            os.fsync(f.fileno())
            f.close()
        except:
            print "Error: can't write to %s." % new_fn
            return
        
        try:
            secure_replace_file(self.fn, new_fn)
        except:
            print "Error: can't generate the new %s file." % self.fn
         
    def get_password(self, i):
        # id is in binary string format
        p = self.password.get(i)
        if(p == None):
            return null_str

        seq, enc = get_seq(p)
        q = mi_decrypt(seq, enc, self.second_enc)
        
db = pass_db(conf_fn)

class master_handler(SocketServer.BaseRequestHandler):
    data = ""
    fin = False
    state = 'start'  # 'got_master', 'no_cfg_yet'
    
    def recv_line(self):
        while(1):
            pos = self.data.find('\n')
            if pos >= 0:
                s = self.data[:pos]
                self.data = self.data[pos + 1:]
                return s
            d = self.request.recv(1024)
            if len(d) == 0:
                # connection closed
                s = self.data
                self.data = ""
                self.fin = True
                return s
            self.data = self.data + d
    
    def handle(self):
        while not self.fin:
            line = self.recv_line()
            header, body = get_header(line)
            if header == 'state':
                self.request.sendall('state %s\n' % self.state)
                continue
            elif header == 'version':
                self.request.sendall('version 0.0.1\n')
                continue
            elif header == "get_pass":
                if self.state == 'got_master':
                    self.request.sendall("pass %s\n" % db.get_password(body))
                else:
                    self.request.sendall("error no master for pass\n")
                continue
            elif header == "master":
                if self.state == 'got_master':
                    self.request.sendall("error got master already\n")
                elif self.state == 'start':
                    raise "[todo]"
                continue
            elif header == 'set_master':
                raise "[todo]"
                continue
            
class master_server(SocketServer.ThreadingMixIn, SocketServer.UnixStreamServer):
    pass

def start_service(unixsock):
    try:
        server = master_server(unixsock, master_handler)
        
        # main loop
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
    except:
        print "Error: can't start the master service."

def client(unixsock):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(unixsock)
    try:
        print "get state"
        sock.sendall("state\n")
        response = sock.recv(1024)
        print response
    finally:
        sock.close()

def usage():
    print """Test usage:
mipass [opt] [id]
   -s pass set pass
   -M pass set master pass
   -m pass master pass
   -k      kill all background missh processes
"""

def test():
    import getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hs:m:M:k")
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    setting = False
    password = null_str
    setting_master = False
    master = null_str
        
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
            raise "[TODO]"
        else:
            assert False, "unhandled option"
    
    # check whether the service is started
    try:
        client(unixsock)
    except:
        try:
            os.remove(unixsock)
            start_service(unixsock)
            client(unixsock)
        except:
            print "can't start service"
    # set/put master pass
    
    # set/get pass
    
    # close
    
    pass

if __name__ == "__main__":
    test()
    
