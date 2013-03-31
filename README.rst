Welcome to

Minimalist Session Manager for SSH
**********************************

Design
======

* store session information in .msh files, including various ssh cmdline options
* use a password keeping service to store encrypted passwords in ~/.missh

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

Lincense
========

A BSD 2-Clause License at https://github.com/LenxWei/MiSSH/blob/master/COPYING
