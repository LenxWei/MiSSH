#!/usr/bin/env python
#-*- coding:utf-8 -*-

from setuptools import setup, find_packages

setup(
    name = "missh",
    version = "0.1.1rc7",
#    packages = find_packages(), #["mipass","missh-nox"],
    py_modules = ["mipass"],
    scripts = ['missh'],
       
    install_requires = ["npyscreen >=2.0pre47", "pycrypto >=2.4.0", "python-daemon >=1.5.5", "pexpect >=2.3"],
    description = "Minimalist Session Manager for SSH",
#    long_description = "A minimalist session manager for Linux/OSX ssh users",
    author = "Lenx Wei",
    author_email = "lenx.wei@gmail.com",
    
    license = "BSD",
    keywords = "ssh session manager",
    platforms = "Independant",
    url = "http://lenx.100871.net/missh",
    classifiers=[
        # Reference: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Environment :: Console :: Curses",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Internet",
        ],
)
