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
 * \-o file   open the session file
 * \-n file   create a new session file
 * \-c        edit or view missh's configuration file
.. * \-C file  use file as the configuration

 * \-k        kill the background password keeping service
 * \-h        show the help information
 * \-v        verbose mode
 
Examples
========

* missh host.msh                # using ~/.missh.conf as the configuration file
* missh -o host.msh
* missh -n new_host.msh
* missh -c
.. * missh -C myssh.conf my_host.msh
   * ./my_host.msh                     # when missh is in the correct path
   * ./my_host.msh -C myssh.conf

* missh -k

Configuration file format
=========================

* master = master_key_sha256
* key = real_key_encrypted_using_master_key_under_aes

Host file format
================

* host = user@host:port
* pass = password_encrypted_using_real_key_under_aes
* # there might be multiple lines of opt:
* opt = adfadfadfasdfs
* opt = adfasfasdfasdf
* opt = adfadfadsfadsf
* forward_only = 1 # or 0

