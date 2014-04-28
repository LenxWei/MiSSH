Welcome to

Minimalist Session Manager for SSH/SFTP
***************************************

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

Upgrade::

   sudo easy_install -U missh

.. _easy_install: https://pypi.python.org/pypi/setuptools 

Command line
============

missh [opt] [file_path]
 -o             open the session file
 -n             create a new session file
 -m             change the master password
 -t timeout     change the timeout of caching the master password, in minutes
 -k             kill the background password keeping service
 -r             reconnect automatically after disconnection
 -f             use sftp to connect the host
 -h             show the help information
 -v             verbose mode

.. * \-C file  use file as the configuration
 
Notice 
======

Please **DO NOT** change the term size **AFTER** login, otherwise the term might get stuck.
If it got stuck, you need to log out and log in again.
This is a problem of the term, not MiSSH :)

Examples
========

* missh host.msh
* missh -o host.msh
* missh -n new_host.msh
* missh -f host.msh
* missh -m
* missh -t 120

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
 │ % sftp options use # as the line header                                      │
 │ # -r                                                                         │
 │                                                                              │
 │                                                                              │
 │                                                               Cancel    OK   │
 └──────────────────────────────────────────────────────────────────────────────┘

.. Edit the configuration::

Session file format
================

* host = user\@host:port
* # there might be multiple lines of opt:
* opt = -D 1080
* opt = -L 5901
* opt = -R 8080 

Configuration file format
=========================

* timeout = 120
* master = NONCE,mi_hash(master_key)
* host_sha256 = NONCE,key_encrypted_using_master1024_key_under_aes

License
=======

BSD 2-Clause License at https://github.com/LenxWei/MiSSH/blob/master/COPYING
