Welcome to

Minimalist Session Manager for SSH
**********************************

Design
======

* store session information in .msh files, including various ssh cmdline options
* use a password keeping service to store encrypted passwords in ~/.missh

Platforms
=========

MiSSH is written in Python 2.7. It should work well on most POSIX platforms.
I have tested it on Mac OSX, Linux and Cygwin.

Install
=======

please use easy_install_ to install missh::

   sudo easy_install missh

.. _easy_install: https://pypi.python.org/pypi/setuptools 

Command line
============

missh [opt] [file_path]
 -o    open the session file
 -n    create a new session file
 -c    edit or view missh's configuration file
 -k    kill the background password keeping service
 -h    show the help information
 -v    verbose mode

.. * \-C file  use file as the configuration
 
Examples
========

* missh host.msh
* missh -o host.msh
* missh -n new_host.msh
* missh -c
* missh -k

.. * missh -C myssh.conf my_host.msh
   * ./my_host.msh                     # when missh is in the correct path
   * ./my_host.msh -C myssh.conf

Screen shots
============

Open or create a seesion file::

 ┌ MiSSH - test.msh ────────────────────────────────────────────────────────────┐
 │                                                                              │
 │ Host:           user@host.net:22                                             │
 │ Password:       ---                                                          │
 │ Other options:                                                               │
 │                                                                              │
 │ % set dynamic socks proxy                                                    │
 │ -D 1080                                                                      │
 │                                                                              │
 │ % forward a local port to a service at a remote port, e.g. vnc @ host:1      │
 │ % -L 5901                                                                    │
 │ % -L 5901:1.2.3.4:5901                                                       │
 │                                                                              │
 │ % forward a remote port to a service at a local port                         │
 │ % -R 8080                                                                    │
 │                                                                              │
 │                                                                              │
 │                                                                              │
 │ [ ]  Forward only?                                                           │
 │                                                                              │
 │                                                                              │
 │                                                                              │
 │                                                               Cancel    OK   │
 └──────────────────────────────────────────────────────────────────────────────┘

.. Edit the configuration::

Host file format
================

* host = user\@host:port
* forward = 1 # or 0
* # there might be multiple lines of opt:
* opt = adfadfadfasdfs
* opt = adfasfasdfasdf
* opt = adfadfadsfadsf

Configuration file format
=========================

* timeout = 120
* master = NONCE,mi_hash(master_key)
* host_sha256 = NONCE,key_encrypted_using_master1024_key_under_aes

License
=======

BSD 2-Clause License at https://github.com/LenxWei/MiSSH/blob/master/COPYING
