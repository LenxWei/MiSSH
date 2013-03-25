#!/usr/bin/env python

# a server provides password cache and lookup service
# depend on pycrypto, python-daemon

# password format:
# id_md5_hashed_and_hex = seq,pass_aes_encrypted_by_master_key_and_hex
# hex: binascii.b2a_hex(s)
# seq is used to generate the IV, sha256 using the master key

# master key:
# master = maseter_key_md5_first_4_bytes_and_hex

'''A password keeping service.

.. moduleauthor:: Lenx Wei <lenx.wei@gmail.com>
'''

from Crypto.Hash import MD5, SHA256
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

import socket
import threading
import SocketServer
import os
import time 
import sys

verbose = False


conf_fn = "~/.missh"
conf_fn = os.path.expanduser(conf_fn)

unixsock = "~/.missh.sock"
unixsock = os.path.expanduser(unixsock)

server = 0

# if critical_error is True, the server must exit after informing the clients.
critical_error = False

# utility functions

def kill_self():
    os.kill(os.getpid(), 9)

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

def get_resp_val(line):
    pos = line.find(":")
    if(pos < 0):
        return None
    return line[pos + 1:].strip()
    
def is_resp_err(line):
    '''check whether the response is err or not.
    
    :param line: the whole response line.
    :returns: True when sth is wrong, False when ok.
    '''
    if line == None or line == "":
        return True
    if line.lower().startswith("error:"):
        return True
    return False

def get_header(s):
    '''
    split the line using ' '.
    
    :param s: the input string.
    :returns: the header, the tail.
    '''
    pos = s.find(' ')
    if(pos > 0):
        return s[:pos].lower(), s[pos + 1:]
    return s.lower(), ''
    
def mi_getseq(enc):
    pos = enc.find(',')
    if pos >= 0:
        try:
            seq = int(enc[:pos])
            return seq
        except:
            pass
    print "bad seq:", enc
    return 0

def gen_AES_param(seq, key):
    m = SHA256.new(key)
    k = m.digest()  # 32bytes
    m.update(str(seq))
    iv = m.digest()[:16]
    return k, iv

def mi_decrypt(enc, key):
    '''decrypt an encrypted password.
    
    :param enc: the encrypted password
    :param key: the key
    :returns: the plain if succeeds, None otherwise
    '''
    seq = None
    pos = enc.find(',')
    if pos >= 0:
        try:
            seq = int(enc[:pos])
        except:
            pass
    if seq == None:
        print "bad seq:", enc
        return None
    
    try:
        body = a2b_hex(enc[pos + 1:])
    except:
        print "bad enc:", enc
        return None
    
    k, iv = gen_AES_param(seq, key)
    obj = AES.new(k, AES.MODE_CBC, iv)
    try:
        plain = obj.decrypt(body)
    except Exception, err:
        print str(err)
        return None
    
    return plain.lstrip('\n')

def mi_encrypt(seq, plain, key):
    """encrypt a plain password.
    
    algorithm::

       key1 = SHA256(key)
       iv = SHA256(key, str(seq))
       body = plain padded using '\\n' to be aligned with 32bytes
       enc = AES.CBC(body, key1, iv)
       encrypted password = seq,enc
    
    :param seq: a number, used to generate the IV
    :param plain: the plain password
    :param key: a string, as the key
    :returns: the encrypted password
    """
    k, iv = gen_AES_param(seq, key)
    obj = AES.new(k, AES.MODE_CBC, iv)
    
    body = plain + '\n' * (32 - (len(plain) - 1) % 32 - 1)
    enc = obj.encrypt(body)
    return "%d,%s" % (seq, b2a_hex(enc))

def get_seq(s):
    p = s.find(",")
    if(p > 0):
        return int(s[:p]), s[p + 1:]
    else:
        return 0, s[p + 1:]
    
ms_start = 0
ms_got_master = 1
ms_void_cfg = 2

# configuration file
class pass_db:
    '''
    the password database
    
    Notice: use self.master_lock to keep threading safety.
    '''
    fn = None
    master = None
    master_hash = None
    master_lock = None
    password_enc = {}  # id:pass, as in file
    seq = 0  # for IV
    timeout = 120  # in min
    init_ok = False
    
    def __init__(self, fn):
        '''constructor.
        
        read cfg from fn.
        
        :param fn: the configuration file name
        '''
        self.fn = fn
        self.init_ok = False
        self.read_cfg()
        self.master_lock = threading.RLock()
        
    def fname(self):
        return self.fn
    
    def read_cfg(self):
        '''
        read configuration from file
        '''
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
                        # print "master:",val
                    elif(key == "timeout"):
                        self.timeout = int(val)
                        # print "timeout:", val
                    elif(key == ""):
                        raise "no key"
                    else:
                        seq, enc = get_seq(val)
                        if(self.seq < seq):
                            self.seq = seq
                        self.password_enc[key] = val
                except:
                    print "error config line #%d : %s" % (line_cnt, line)
                    continue
            
            self.init_ok = self.master_hash != None
            # print "init:", self.init_ok
            f.close() 
        except:
            print "bad configuration file:", self.fn
            return
        
    def get_master_hash(self, master):
        '''master hash.
        
        only store master_hash in cfg.
        
        algorithm::
        
           hex(MD5(master))[:8]
        
        :param master: the master key
        :returns: the hash   
        '''
        assert master != None
        
        m = MD5.new()
        m.update(master)
        return m.hexdigest()[:8]
        
    def check_id(self, id):
        """validate an id that it should only contain alpha or number characters.
        
        :param id: the id
        :returns: True or False
        """
        return id.is_alnum();
    
    def set_pass(self, id, pwd):
        """set password for id
        
        self.master should be valid.
        
        :param id: the user id
        :param pwd: the new password
        :returns: True if succeeds, False otherwise
        """
        assert self.master != None
        if not self.check_id(id):
            return False
        
        self.seq = self.seq + 1
        with self.master_lock:
            self.password_enc[id] = mi_encrypt(self.seq, pwd, self.master)
        return self.write_cfg()
        
    def get_pass(self, id):
        """get password of id
        
        self.master should be valid.
        
        :param id: the user id
        :returns: the password, None if not existed
        """
        
        assert self.master != None
        
        with self.master_lock:
            enc = self.password_enc.get(id)
            if enc != None:
                return mi_decrypt(enc, self.master)
            return None
    
    def set_master(self, master):
        """set a new master key.
        
        self.master should be valid when some passwords already exist.
        
        :param master: the new master key
        :returns: True if succeeds, False otherwise
        """
        
        new_pass = {}
        if len(self.password_enc) > 0 and self.master == None:
            return False
        
        with self.master_lock:
            for i in self.password_enc:
                self.seq = self.seq + 1
                new_pass[i] = mi_encrypt(self.seq, mi_decrypt(self.password_enc[i], self.master), master)
            
            self.master = master
            self.password_enc = new_pass
        
            return self.write_cfg()
        
    def check_master(self, master):
        ''' Check whether the master is correct or not.
        
        If master is correct, remember the master key.
        
        :param master: the key to be tested
        :returns: 1 if succeeds, 0 otherwise
        '''
        
        with self.master_lock:
            if self.master_hash == None or (self.get_master_hash(master) == self.master_hash):
                self.master = master
                return 1
            return 0
            
    def write_cfg(self):
        '''write the new configuration file.
        
        using two files to replace each other, in order to control the potential leakage.
        '''
        
        if(self.master == None):
            print "Error: can't write cfg without a master password"
            return False
        
        new_fn = self.fn + ".new"
        old_fn = self.fn + ".old"
        try:
            os.rename(old_fn, new_fn)
        except:
            pass
        
        with self.master_lock:
            # write to new_fn
            try:
                try:
                    f = open(new_fn, 'r+b')
                except:
                    f = open(new_fn, 'wb')
                f.write("# don't edit this file manually. please use 'missh -c'.\n")
                f.write("timeout = %d\n" % self.timeout)
                f.write("master = %s\n" % self.get_master_hash(self.master))
                f.write("\n")
                for i in self.password_enc:
                    f.write("%s = %s\n" % (i, self.password_enc[i]))
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
                f.close()
            except Exception, e:
                print str(e)
                print "Error: can't write to %s." % new_fn
                critical_error = True
                return False
        
        try:
            os.rename(self.fn, old_fn)
        except:
            print "Error: can't rotate %s" % self.fn
            critical_error = True
            return False
        
        try:
            os.rename(new_fn, self.fn)
        except:
            print "Error: can't replace %s" % self.fn
            critical_error = True
            return False
        return True

    def state(self):
        """return the current state.
        
        There are 3 possible states:
        
        * ms_void_cfg : the database is not correctly initialized.
        * ms_start : the database is opened, but the master key is not known.
        * ms_got_master : the database is opened with a correct master key.
        """
        if self.init_ok == None:
            return ms_void_cfg
        elif self.master == None:
            return ms_start
        else:
            return ms_got_master
        
db = pass_db(conf_fn)

class master_handler(SocketServer.BaseRequestHandler):
    """The unix socket service for pass_db.
    """
    
    data = ""
    fin = False

    def state(self):
        return db.state()
    
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
    
    def check_error(self):
        if critical_error:
            self.request.sendall("Error: updating the config file %s failed. The password service must stop. Please check its privilege.\n" % db.fname())
            time.sleep(1)
            kill_self()

    def handle(self):
        """handle input.
        
        messages:
        
        * state
            * state: [0|1|2]
        * version
            * version 0.0.1
        * check_master master_key
            * Error: no valid config file
            * check_master: [0|1]
        * set_master master_key
            * set_master: master_key
            * Error: updating the config file %s failed. The password service must stop. Please check its privilege.
            * Error: need old master key for existing passwords
        * get_pass id
            * Error: 'id' doesn't exist
            * Error: no master key
            * Error: invalid id '%s'
            * get_pass: %s
        * set_pass id
            * Error: bad input '%s'
            * Error: no master key
            * Error: updating the config file %s failed. The password service must stop. Please check its privilege.
            * Error: invalid id '%s'
            * set_pass: %s, %s
        * kill
            * kill: pid
        * unknown_header: %s
        """
        # [a:master:server:handle]
        while not self.fin:
            line = self.recv_line()
            header, body = get_header(line)
            if header == 'state':
                self.request.sendall('state: %s\n' % self.state())
                continue
            elif header == 'version':
                self.request.sendall('version: 0.0.1\n')
                continue
            elif header == "get_pass":
                if self.state() == ms_got_master:
                    pwd = db.get_pass(body)
                    if pwd == None:
                        self.request.sendall("Error: '%s' doesn't exist\n" % body)
                    else:
                        self.request.sendall("get_pass: %s\n" % pwd)
                else:
                    self.request.sendall("Error: no master key\n")
                continue
            elif header == "check_master":
                if self.state() == ms_void_cfg:
                    self.request.sendall("Error: no valid config file\n")
                    continue
                r = db.check_master(body)
                self.request.sendall("check_master: %s\n" % str(r))
                continue
            elif header == 'set_master':
                if db.set_master(body):
                    if db.write_cfg():
                        self.request.sendall("set_master: %s\n" % body)
                    else:
                        self.check_error()
                        assert 0  # should never arrive here
                else:
                    self.request.sendall("Error: needs old master key for existing passwords\n")
                continue
            elif header == 'set_pass':
                pos = body.find(",")
                if(pos <= 0):
                    self.request.sendall("Error: bad input '%s'\n" % body)
                    continue
                if self.state() != ms_got_master:
                    self.request.sendall("Error: no master key\n")
                    continue
                id = body[:pos]
                pwd = body[pos + 1:]
                if not db.set_pass(id, pwd):
                    self.check_error()
                    self.request.sendall("Error: invalid id '%s'\n" % id)
                    continue
                self.request.sendall("set_pass: %s, %s\n" % (id, pwd))
                continue
            elif header == 'kill':
                self.request.sendall("kill: %d\n" % os.getpid())
                try:
                    os.remove(unixsock)  # [FIXME]
                except:
                    pass
                kill_self()
                break
            elif header == '':
                continue
            print "unknown_header:'%s'" % header
            
class master_server(SocketServer.ThreadingMixIn, SocketServer.UnixStreamServer):
    pass

def start_service(unixsock):
    """Start the password keeping service.
    
    :param unixsock: the socket file
    """
    server = master_server(unixsock, master_handler)
    
    # main loop
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(db.timeout * 60)
    # todo: check time, delay if needed
    
    server.shutdown()
    os.remove(unixsock)
    os._exit(0)

def start_service_daemon(unixsock):
    '''Start the service daemon.
    
    :param unixsock: the socket filename
    '''
    try:
        pid = os.fork()
        if(pid > 0):
            time.sleep(1)
        else:
            import daemon
            
            with daemon.DaemonContext():
                start_service(unixsock)
    except:
        print "Error: can't start the master service."

def url_hash(url):
    """generate the id used in the password keeping service.
    
    algorithm::
    
       hex(SHA256(url))[:32]
    """
    
    assert url != None
    
    m = SHA256.new()
    m.update(url)
    return m.hexdigest()[:32]

# [a:master:client]
class client:
    """The client to communicate with the password keeping service.
    """
    
    sock_fn = ""
    connected = False
    master_status = 0  # 0 unconnected, 1 got master, -1 have an unknown master, -2 need to set a master
    data = ""
    
    def __init__(self, unixsock):
        self.sock_fn = unixsock
        
    def recv_line(self):
        '''get a line from the receive buffer.
        
        :returns: the input line
        '''
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
        
    def _connect(self):
        '''connect to the password keeping service.
        '''
        if self.connected:
            return
        
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.connect(self.sock_fn)
            self.connected = True

            # print "get state"
            self.sock.sendall("state\n")
            response = self.recv_line()
            state = get_resp_val(response)
            if state == str(ms_got_master):
                self.master_status = 1
            elif state == str(ms_void_cfg):
                self.master_status = -2
            else:
                self.master_status = -1
                
            # print "resp:", response
        except Exception, err:
            if verbose:
                print "Error:", str(err)
            self.sock.close()
            if verbose:
                print "Error: can't connect to the password keeping service."
            self.connected = False
            pass

    def connect(self, try_hard=True):
        self._connect()
        if try_hard and not self.connected:
            try:
                os.remove(self.sock_fn)
            except:
                pass
            try:
                start_service_daemon(self.sock_fn)
            except:
                pass
            self.connect()
            if not self.connected:
                print "Error: can't connect to the master password service."
                sys.exit(2)

    def kill(self):
        '''kill the service.
        
        :returns: the response.
        '''
        if not self.connected:
            self.connect(False)
        if self.connected:
            self.sock.sendall("kill\n")
            resp = self.recv_line()
            self.close()
            return resp
        else:
            return "no password keeping service found"
        
    def need_master(self):
        '''test whether a master key is needed.
        
        :returns: 0 unconnected, 1 got master, -1 have an unknown master, -2 need to set a master
        '''
        if not self.connected:
            self.connect()
        
        return self.master_status
    
    def check_master(self, master):
        '''check and set the master key.
        
        :param master: the master key.
        :returns: the response
        '''
        assert self.connected
        self.sock.sendall("check_master %s\n" % master)
        resp = self.recv_line()
        if not is_resp_err(resp):
            self.master_status = 1
        return resp
        
    def set_master(self, master):
        '''set the master key.
        
        :param master: the master key.
        :returns: the response.
        '''
        assert self.connected
        self.sock.sendall("set_master %s\n" % master)
        resp = self.recv_line()
        if not is_resp_err(resp):
            self.master_status = 1
        return resp
        
    def set_pass(self, url, password):
        '''set the password for url.
        
        :param url: the service.
        :param password: the password.
        :returns: the response.
        '''
        assert self.connected
        self.sock.sendall("set_pass %s,%s\n" % (url_hash(url), password))
        resp = self.recv_line()
        # print "set_pass, resp:", resp
        return resp
        
    def get_pass(self, url):
        '''get the password.
        
        :param url: url of the service.
        :returns: the response.
        '''
        assert self.connected
        self.sock.sendall("get_pass %s\n" % url_hash(url))
        resp = self.recv_line()
        return resp
    
        # print "get_pass, resp:", resp
        # if resp.startswith("get_pass: "):
        #    return resp[len("get_pass: "):]
        # return None
        
    def close(self):
        '''close the service.
        '''
        # print "closed"
        if self.connected:
            try:
                self.sock.close()
            except:
                pass
            self.connected = False
         
# interface for other modules
# [a:login:get_password]
def get_password(host):
    c = client(unixsock)
    c.connect()  # should get status, and then determine whether to require the master key
    # [a:login:get_password:connect]
        
    if not c.got_master:
        # [a:login:get_password:ask master]
        # ask master password
        import getpass
        master_pwd = getpass.getpass("master password:")
        c.check_master(master_pwd)
        # [FIXME]

        if not c.got_master:
            print "Error: no correct master password."
            sys.exit(1)
                
    if verbose:
        print "host hash is", url_hash(host)
    resp = c.get_pass(host)
    if not is_resp_err(resp):
        pwd = get_resp_val(resp)
    else:
        pwd = None
    c.close()
    return pwd
        
def update_password(host, pwd):
    c = client(unixsock)
    c.connect()  # should get status, and then determine whether to require the master key
        
    if not c.got_master:
        # ask master password
        import getpass
        master_pwd = getpass.getpass("master password:")
        c.check_master(master_pwd)
        # [FIXME]

        if not c.got_master:
            print "Error: no correct master password."
            sys.exit(2)
                
    if verbose:
        print "host hash is", url_hash(host)
    c.set_pass(host, pwd)
    c.close()
