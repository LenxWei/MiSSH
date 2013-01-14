# a server provides password cache and lookup service
# depend on pycrypto, python-daemon

# password format:
# id_md5_hashed_and_hex = seq,pass_aes_encrypted_by_master_key_and_hex
# hex: binascii.b2a_hex(s)
# seq is used to generate the IV, sha256 using the master key

# master key:
# master = maseter_key_md5_first_4_bytes_and_hex

from Crypto.Hash import MD5, SHA256
from Crypto.Cipher import AES
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

server = 0
# utility functions

def remove_remark(line):
    pos = line.find("#")
    if(pos >= 0):
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
    except Exception, err:
        print str(err)
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
    '''
    split the line using ' '
    '''
    pos = s.find(' ')
    if(pos > 0):
        return s[:pos].lower(), s[pos + 1:]
    return s.lower(), ''
    
def mi_getseq(enc):
    pos=enc.find(',')
    if pos>=0:
        try:
            seq=int(enc[:pos])
            return seq
        except:
            pass
    print "bad seq:",enc
    return 0

def gen_AES_param(seq, key):
    m=SHA256.new(key)
    k=m.digest() # 32bytes
    m.update(str(seq))
    iv=m.digest()[:16]
    return k,iv

# encrypt/decrypt
def mi_decrypt(enc, key):
    # [todo]
    seq=None
    pos=enc.find(',')
    if pos>=0:
        try:
            seq=int(enc[:pos])
        except:
            pass
    if seq==None:
        print "bad seq:",enc
        return ""
    
    try:
        body=a2b_hex(enc[pos+1:])
    except:
        print "bad enc:", enc
        return ""
    
    k, iv=gen_AES_param(seq, key)
    obj=AES.new(k, AES.MODE_CBC, iv)
    try:
        plain=obj.decrypt(body)
    except Exception, err:
        print str(err)
        return ""
    
    return plain.lstrip('\n')

def mi_encrypt(seq, plain, key):
    k, iv=gen_AES_param(seq, key)
    obj=AES.new(k, AES.MODE_CBC, iv)
    
    body=plain + '\n' * (32 - (len(plain)-1) % 32 -1)
    enc=obj.encrypt(body)
    return "%d,%s" % ( seq, b2a_hex(enc))

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
    master = null_str
    password_enc = {}  # id:pass, as in file
    seq = 0  # for IV
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
                        self.master_hash = val
                    elif(key == "timeout"):
                        self.timeout = int(val)
                        #print "timeout:", val
                    elif(key == ""):
                        raise "no key"
                    else:
                        seq,enc=get_seq(val)
                        if(self.seq < seq):
                            self.seq=seq
                        self.password_enc[key] = val
                except:
                    print "error config line #%d : %s" % (line_cnt, line)
                    continue
            
            self.init_ok = True
            f.close() 
        except:
            print "bad configuration file:", self.fn
            return
        
    def get_master_hash(self, master):
        assert master!=null_str
        
        m=MD5.new()
        m.update(master)
        return m.hexdigest()[:8]
        
    def set_pass(self, id, pwd):
        self.seq=self.seq+1
        self.password_enc[id]=mi_encrypt(self.seq, pwd, self.master)
        
    def get_pass(self, id):
        enc=self.password_enc.get(id)
        if enc!=None:
            return mi_decrypt(enc, self.master)
        return None
    
    def set_master(self, master):
        # update password_enc
        
        new_pass={}
        for i in self.password_enc:
            self.seq=self.seq+1
            new_pass[i]=mi_encrypt(self.seq, mi_decrypt(self.password_enc[i], self.master), master)
        self.master=master
        self.password_enc=new_pass
        
    def check_master(self, master):
        if(self.get_master_hash(master)==self.master_hash):
            self.master=master
            return 1
        return 0
            
    def write_cfg(self):
        if(self.master==null_str):
            print "Error: can't write cfg without a master password"
            return
        
        new_fn = self.fn + ".new"
        # write to new_fn
        try:
            f = open(new_fn, 'wb')
            f.write("# don't edit this file manually. please use 'missh -c'.\n")
            f.write("timeout = %d\n" % self.timeout)
            f.write("master = %s\n" % self.get_master_hash(self.master))
            f.write("\n")
            for i in self.password_enc:
                f.write("%s = %s\n" % (i, self.password_enc[i]))
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

ms_start="start"
ms_got_master="got_master"
ms_no_cfg="no_cfg_yet"

class master_handler(SocketServer.BaseRequestHandler):
    data = ""
    fin = False
    state = ms_start # 'got_master', 'no_cfg_yet'
    
    def recv_line(self):
        """
        return a line without '\n' from the buffer
        """
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
                if self.state == ms_got_master:
                    self.request.sendall("pass %s\n" % db.get_pass(body))
                else:
                    self.request.sendall("Error: no master for pass\n")
                continue
            elif header == "check_master":
                r=db.check_master(body)
                if(r):
                    if self.state == ms_start:
                        self.state=ms_got_master
                self.request.sendall("check_master: %s\n" % str(r))
                continue
            elif header == 'set_master':
                db.set_master(body)
                if self.state == ms_start:
                    self.state=ms_got_master
                db.write_cfg()
                self.request.sendall("update master: %s\n" % body)
                continue
            elif header == 'set_pass':
                pos=body.find(",")
                if(pos<=0):
                    self.request.sendall("Error: bad id %s\n" % body)
                    continue
                id=body[:pos]
                pwd=body[pos+1:]
                db.set_pass(id,pwd)
                db.write_cfg()
                self.request.sendall("update pass: %s, %s\n" % (id,pwd))
                continue
            elif header == 'kill':
                self.request.sendall("kill %d\n" % os.getpid() )
                try:
                    os.remove(unixsock) # [FIXME]
                except:
                    pass
                os.kill(os.getpid(),9)
                break
            elif header == '':
                continue
            print "unknown header:'%s'" % header
            
class master_server(SocketServer.ThreadingMixIn, SocketServer.UnixStreamServer):
    pass

def start_service(unixsock):
    server = master_server(unixsock, master_handler)
    
    # main loop
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(db.timeout*60)
    server.shutdown()
    os.remove(unixsock)
    os._exit(0)

def start_service_daemon(unixsock):
    try:
        pid=os.fork()
        if(pid>0):
            time.sleep(1)
        else:
            import daemon
            
            with daemon.DaemonContext():
                start_service(unixsock)
    except:
        print "Error: can't start the master service."

class client:
    sock_fn=""
    connected=False
    data=""
    
    def __init__(self, unixsock):
        self.sock_fn = unixsock
        
    def recv_line(self):
        assert self.connected
        while(1):
            pos = self.data.find('\n')
            if pos >= 0:
                s = self.data[:pos]
                self.data = self.data[pos + 1:]
                return s
            d = self.sock.recv(1024)
            if len(d) == 0:
                # connection closed
                s = self.data
                self.data = ""
                self.close()
                return s
            self.data = self.data + d
        
        
    def connect(self):
        if self.connected:
            return
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.connect(self.sock_fn)
            self.connected=True

            print "get state"
            self.sock.sendall("state\n")
            response = self.recv_line()
            print "resp:", response
        except Exception, err:
            print "Error:", str(err)
            self.sock.close()
            print "Error: can't connect"
            self.connected=False
            pass

    def kill(self):
        assert self.connected
        self.sock.sendall("kill\n")
        resp=self.recv_line()
        print "kill, resp:",resp
        self.close()
        
    def set_master(self, master):
        assert self.connected
        self.sock.sendall("set_master %s\n" % master)
        resp = self.recv_line()
        print "set_master, resp:", resp
        
    def set_pass(self, id, password):
        assert self.connected
        self.sock.sendall("set_pass %s,%s\n" % (id,password))
        resp = self.recv_line()
        print "set_pass, resp:", resp
        
    def get_pass(self, id):
        assert self.connected
        self.sock.sendall("get_pass %s\n" % id)
        resp = self.recv_line()
        print "get_pass, resp:", resp
        
    def check_master(self, master):
        assert self.connected
        self.sock.sendall("check_master %s\n" % master)
        resp = self.recv_line()
        print "check_master, resp:", resp
        
    def close(self):
        print "closed"
        if self.connected:
            try:
                self.sock.close()
            except:
                pass
            self.connected=False
         
def usage():
    print """Test usage:
mipass [opt] [id]
   -d      front daemon mode
   -s pass set pass
   -M pass set master pass
   -m pass master pass
   -k      kill all background missh processes
"""

def test():
    import getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dhs:m:M:k")
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    id=None
    if len(args)>0:
        id=args[0]
        
    #secure_replace_file(conf_fn, conf_fn+".new")
    setting = False
    password = null_str
    setting_master = False
    master = null_str
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
            kill=True
        elif o == '-d':
            front_server=True
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
    
    c=client(unixsock)
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
    if setting_master:
        c.set_master(master)
    else:
        c.check_master(master)
    
    if setting:
        c.set_pass(id, password)
    else:
        c.get_pass(id)
        
    # set/get pass
    
    # close
    c.close()

if __name__ == "__main__":
    test()
    
