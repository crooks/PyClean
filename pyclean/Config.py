#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# Copyright (C) 2012 Steve Crook <steve@mixmin.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# This file forms the start on some work to allow newsgroup filters to be
# added and auto-expired after a defined period.

import ConfigParser
import os
import sys

def makedir(d):
    """Check if a given directory exists.  If it doesn't, check if the parent
    exists.  If it does then the new directory will be created.  If not then
    sensible options are exhausted and the program aborts.

    """
    if not os.path.isdir(d):
        parent = os.path.dirname(d)
        if os.path.isdir(parent):
            os.mkdir(d, 0700)
            sys.stdout.write("%s: Directory created.\n" % d)
        else:
            msg = "%s: Unable to make directory. Aborting.\n" % d
            sys.stdout.write(msg)
            sys.exit(1)


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

# Logging
config.add_section('logging')
config.set('logging', 'level', 'info')
config.set('logging', 'format', '%(asctime)s %(levelname)s %(message)s')
config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')
config.set('logging', 'retain', 7)

# Binary
config.add_section('binary')
config.set('binary', 'lines_allowed', 15)

# The path section is a bit tricky. First off we try to read a default config
# file.  This can define the path to everything, including the pyclean.cfg
# config file.
config.add_section('paths')
# In accordance with Debian standards, we'll look for /etc/default/pyclean.
# This file can define the path for pyclean's etc, which includes the
# pyclean.cfg file.  The location of the default file can be overridden by
# setting the 'PYCLEAN' environment variable.
if 'PYCLEAN' in os.environ:
    default = os.environ['PYCLEAN']
else:
    default = os.path.join('/', 'etc', 'default', 'pyclean')
if os.path.isfile(default):
    config.read(default)
# By default, all the paths are subdirectories of the homedir.
homedir = os.path.expanduser('~')
# Define the basedir for pyclean.  By default this will be ~/pyclean
basedir = os.path.join(homedir, 'pyclean')
# If the default file hasn't specified an etc path, we need to assume a
# default.  Usually /usr/local/news/pyclean/etc.
if not config.has_option('paths', 'etc'):
    config.set('paths', 'etc', os.path.join(basedir, 'etc'))
    # At this point, we know the basedir is going to be required so we
    # attempt to create it.
    makedir(basedir)
makedir(config.get('paths', 'etc'))
# Under all circumstances, we now have an etc path.  Now to check
# if the config file exists and if so, read it.
configfile = os.path.join(config.get('paths', 'etc'), 'pyclean.cfg')
if os.path.isfile(configfile):
    config.read(configfile)

if not config.has_option('paths', 'log'):
    config.set('paths', 'log', os.path.join(basedir, 'log'))
    # As with the etc section above, we know basedir is required now. No
    # harm in trying to create it multiple times.
    makedir(basedir)
makedir(config.get('paths', 'log'))

# The following lines can be uncommented in order to write a config file. This
# is useful for creating an example file.
#with open('example.cfg', 'wb') as configfile:
#    config.write(configfile)

