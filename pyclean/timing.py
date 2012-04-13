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

import datetime

def future(days=0, hours=0, mins=0, secs=0):
    return now() + datetime.timedelta(days=days, hours=hours,
                                      minutes=mins, seconds=secs)

def timestamp(stamp):
    return stamp.strftime("%Y-%m-%d %H:%M:%S")

def datestamp(stamp):
    return stamp.strftime("%Y-%m-%d")

def dateobj(datestr):
    """Take a string formated date (yyyymmdd) and return a datetime object."""
    return datetime.datetime.strptime(datestr, '%Y%m%d')

def now():
    return datetime.datetime.utcnow()
    #return datetime.datetime.now()


if (__name__ == "__main__"):
    print timestamp(future(hours=1))
