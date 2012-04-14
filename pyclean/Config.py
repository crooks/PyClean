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

# By default, all the paths are subdirectories of the homedir. We define the
# actual paths after reading the config file as they're relative to basedir.
config.add_section('paths')
homedir = os.path.expanduser('~')

# Define the basedir for pyclean.  By default this will be ~/pyclean
basedir = os.path.join(homedir, 'pyclean')
makedir(basedir)

if 'PYCLEANETC' in os.environ:
    config.set('paths', 'etc', os.environ['PYCLEANETC'])
else:
    config.set('paths', 'etc', os.path.join(basedir, 'etc'))
makedir(config.get('paths', 'etc'))

if 'PYCLEANLOG' in os.environ:
    config.set('paths', 'log', os.environ['PYCLEANLOG'])
else:
    config.set('paths', 'log', os.path.join(basedir, 'log'))
makedir(config.get('paths', 'log'))

# Logging
config.add_section('logging')
config.set('logging', 'level', 'info')
config.set('logging', 'format', '%(asctime)s %(levelname)s %(message)s')
config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')
config.set('logging', 'retain', 7)

# Binary
config.add_section('binary')
config.set('binary', 'lines_allowed', 15)

#with open('example.cfg', 'wb') as configfile:
#    config.write(configfile)

configfile = os.path.join(config.get('paths', 'etc'), 'pyclean.cfg')
if os.path.isfile(configfile):
    config.read(configfile)
