#!/usr/bin/env python
import npyscreen
import sys
import os
import pexpect
import getopt
import mipass

default_opt = \
"""% set dynamic socks proxy
% -D 1080

% forward local port to remote port, e.g. vnc @ host:1
% -L 5901
% -L 5901:1.2.3.4:5901

% forward remote port to local port
% -R 8080"""
    
c=None

class MisshApp(npyscreen.NPSApp):
    def __init__(self, fn, host, password, opt, fwd):
        self.fn = fn
        self.hostn = host
        self.passwordn = password
        self.optn = opt
        self.fwdn = fwd
    
    def main(self):
        npyscreen.setTheme(npyscreen.Themes.TransparentThemeDarkText)

        F = npyscreen.ActionForm(name="MiSSH - " + self.fn)
        F.on_ok = self.on_ok
        F.while_editing = self.on_switch
        
        self.host = F.add(npyscreen.TitleText, name="Host:", value=self.hostn)
#        self.port = F.add(npyscreen.TitleText, name = "Port:", value=self.portn )
        self.password = F.add(npyscreen.TitlePassword, name="Password:", value=self.passwordn)
        F.add(npyscreen.TitleFixedText, name="Other options:", height=1)
        self.options = F.add(npyscreen.MultiLineEdit, value=self.optn, max_height=12)
        self.forward_only = F.add(npyscreen.Checkbox, name="Forward only?", value=self.fwdn)
#        self.forward_only= F.add(npyscreen.TitleMultiSelect, value=self.fwdn,
#                                 name="Mode",values=["Forward only?"],scroll_exit=True)
        self.connect = False
        F.edit()

    def __str__(self):
        return "%s # %s @%s\n%s" % (self.host.value, self.password.value,
                                     self.forward_only.value, self.options.value)

    def on_switch(self):
        if self.host.value != self.hostn:
            ok, pwd=c.get_pass(self.host.value)
            if ok:
                self.password.value=pwd
            self.hostn=self.host.value
    
    def on_ok(self):
        self.connect = True

class MisshCfg(npyscreen.NPSApp):
    def __init__(self, to):
        self.timeoutn=to
        
    def main(self):
        npyscreen.setTheme(npyscreen.Themes.TransparentThemeDarkText)

        F = npyscreen.ActionForm(name="MiSSH Configuration",)
#        self.main_password = F.add(npyscreen.TitlePassword, name="Main password:")
        self.timeout = F.add(npyscreen.TitleText, name="Password cache timeout (in minutes):",
                             value=str(self.timeoutn))
        self.save = False
        F.on_ok = self.on_ok
        # This lets the user play with the Form.
        F.edit()
    
    def __str__(self):
        return "%s" % (self.timeout.value)

    def on_ok(self):
        self.save = True
        
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

class missh_cfg:
    fn = ""
    def __init__(self, fn, new=False):
        self.fn = fn
        self.host = None
        self.opt = []
        self.fwd = 0
        if not new:
            self.read_cfg()
            
    def cmdline(self):
        o = []
        for i in self.opt:
            if not i.strip().startswith("%"):
                o.append(i)
        return "ssh " + self.host + " " + " ".join(o)
        
    def update(self, host, opt, fwd):
        need_write = False
        if self.host != host:
            self.host = host
            need_write = True
        if self.opt != opt:
            self.opt = opt
            need_write = True
        if self.fwd != fwd:
            self.fwd = fwd
            need_write = True
        if need_write:
            self.write_cfg()

    def write_cfg(self):
        f = open(self.fn, "wb")
        f.write("#!/usr/bin/env missh")
        f.write("# don't edit this file manually. please use 'missh -o'.\n\n")
        
        f.write("host = %s\n" % self.host)
        f.write("forward = %s\n" % self.fwd)
        for i in self.opt:
            f.write("opt = %s\n" % i)
        f.close()
        
            
    def read_cfg(self):
        line_cnt = 0
        try:
            f = open(self.fn, "rb")
            for line in f:
                line_cnt = line_cnt + 1
                
                # strip and remove remarks
                line = remove_remark(line)
                if line == '':
                    continue
                
                # fetch the key and value
                try:
                    key, val = get_key_val(line)
                    if(key == "host"):
                        self.host = val
                    elif(key == "opt"):
                        self.opt.append(val)
                    elif(key == "forward"):
                        self.fwd = int(val)
                    else:
                        raise "bad key"
                except:
                    print "error config line #%d : %s" % (line_cnt, line)
                    continue
            
            f.close() 
        except:
            print "bad configuration file:", self.fn
            return
        
        # import password
        

def usage():
    print "missh 0.1 by LenX (lenx.wei@gmail.com)"
    print """Usage:
missh [opt] [file_path]
   -o      open a session file
   -n      create a new session file
   -c      edit or view missh's configuration file
   -k      kill all background missh processes
   -h      show help information
   -v      verbose mode
"""
    sys.exit(2)

def main():
    global c
    # parse arguments
    fn = "" 
    conf = ""
    kill = False
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvnock")
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        usage()
    
    edit = False
    kill = False
    create = False
    edit_cfg = False
    
    for o, a in opts:
        if o == "-v":
            mipass.verbose = True
        elif o == "-h":
            usage()
            sys.exit()
        elif o == "-o":
            edit = True
        elif o == '-n':
            edit = True
            create = True
        elif o == '-k':
            kill = True
        elif o == '-c':
            edit_cfg = True
        else:
            print "Error: bad options - ( %s : %s )" % (o, a)
            usage()

    if edit_cfg:
        db=mipass.pass_db(mipass.conf_fn)
        App=MisshCfg(db.timeout)
        App.run()
        if App.save:
            try:
                timeout = int(App.timeout.value)
            except:
                timeout = -1
            if timeout > 0:
                db.timeout = timeout
            else:
                print "Bad timeout:", App.timeout.value
            db.write_cfg()
        sys.exit(0)
    
    c=mipass.client(mipass.unixsock)

    if kill:
        ok, resp=c.kill()
        if ok:
            print "The service is stopped."
        else:
            print resp
        sys.exit(0)
    
    if(len(args) == 1):
        fn = args[0]
    else:    
        usage()
        sys.exit(2)

    if edit and not os.path.exists(fn) and not create:
        print "Session file is not found:",fn
        sys.exit(1)
    
    if create and os.path.exists(fn):
        s=raw_input("Session file exists. Are you going to rewrite it? [y/n]")
        if s.lower()=='y' or s.lower()=='yes':
            pass
        else:
            sys.exit(1)

    c.connect()

    # get pwd
    if c.need_master()==-2:
        import getpass
        while 1:
            master_pwd = getpass.getpass("Create the master password:")
            master_pwd2 = getpass.getpass("Please repeat it:")
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
            master_pwd = getpass.getpass("Input the master password:")
            ok, resp = c.check_master(master_pwd)
            print ok, resp
            if not ok:
                print "Please try again. Error:",resp
            else:
                break
        
    # parse msh file
    connect = True
    cfg = missh_cfg(fn, create)
        
    # [a:login:main:get_password]
    if create:
        pwd=""
        cfg.opt=default_opt.split('\n')
    else:
        ok, pwd = c.get_pass(cfg.host)
        
        if not ok:
            pwd=""
    
    if mipass.verbose:
        print "Password:", pwd
    
    # show dialog if needed
    # todo: verbose mode
    if edit:
        App = MisshApp(fn, cfg.host, pwd, "\n".join(cfg.opt), cfg.fwd)
        App.run()
        connect = App.connect
        # update config
        if connect:
            cfg.update(App.host.value, App.options.value.split('\n'), App.forward_only.value)
            # update pwd
            if pwd != App.password.value:
                pwd = App.password.value
                c.set_pass(cfg.host, pwd)
        
    # connect to ssh
    if connect:
        print cfg.cmdline()
        c = pexpect.spawn(cfg.cmdline())
        c.expect("assword:", timeout=300)
        c.sendline(pwd)
        c.interact()

if __name__ == "__main__":
    main()
    
