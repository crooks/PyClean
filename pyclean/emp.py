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

import pyclean.timing
import hashlib
import re
import sys
import logging


class EMP():
    def __init__(self, threshold=3,
                       ceiling=100,
                       maxentries=5000,
                       timedtrim=3600,
                       dofuzzy=False,
                       name=False):
        # Statistics relating to this EMP instance
        if threshold > ceiling:
            raise ValueError('Threshold cannot exceed ceiling')
        # The hash table itself.  Keyed by MD5 hash and containing a hit
        # count.
        self.table = {}
        self.fuzzy_15char = re.compile('\S{15,}')
        self.fuzzy_notletters = re.compile('[^a-zA-Z]')
        # Initialize some defaults
        self.stats = {'name':       name,
                      'nexttrim':   pyclean.timing.future(secs=timedtrim),
                      'processed':  long(0),
                      'accepted':   long(0),
                      'rejected':   long(0),
                      'threshold':  threshold,
                      'ceiling':    ceiling,
                      'maxentries': maxentries,
                      'timedtrim':  timedtrim,
                      'dofuzzy':    dofuzzy}
        logmes = '%(name)s initialized. '
        logmes += 'threshold=%(threshold)s, '
        logmes += 'ceiling=%(ceiling)s, '
        logmes += 'maxentries=%(maxentries)s, '
        logmes += 'timedtrim=%(timedtrim)s'
        logging.info(logmes % self.stats)

    def add(self, content):
        """The content, in this context, is any string we want to hash and
        check for EMP collisions.

        """
        self.stats['processed'] += 1
        if self.stats['dofuzzy']:
            # Strip long strings
            content = re.sub(self.fuzzy_15char, '', content)
            # Remove everything except a-zA-Z
            content = re.sub(self.fuzzy_notletters, '', content).lower()

        # Bail out if the byte length of the content isn't sufficient for
        # generating an effective, unique hash.
        if len(content) < 10:
            return False

        # MD5 is weak in cryptographic terms, but do I care for the purpose
        # of EMP collision checking?  Obviously not or I'd use something else.
        h = hashlib.md5(content).digest()
        if h in self.table:
            # When the ceiling is reached, stop incrementing the count.
            if self.table[h] < self.stats['ceiling']:
                self.table[h] += 1
        else:
            # See if it's time to perform a trim.  We only care about doing
            # this when a new entry is being made.
            if pyclean.timing.now() > self.stats['nexttrim']:
                self._trim()
            elif len(self.table) > self.stats['maxentries']:
                logmes = '%(name)s: Exceeded maxentries of %(maxentries)s'
                logging.warn(logmes % self.stats)
                self._trim()
            # Initialize the md5 entry.
            self.table[h] = 1
        if self.table[h] > self.stats['threshold']:
            # Houston, we have an EMP reject.
            self.stats['rejected'] += 1
            return True
        self.stats['accepted'] += 1
        return False

    def _trim(self):
        """Decrement the counter against each hash.  If the counter reaches
        zero, delete the hash entry.

        """
        self.stats['oldsize'] = len(self.table)
        for h in self.table.keys():
            if self.table[h] >= self.stats['ceiling']:
                logging.info('%s: Ceiling hit for hash %s' % \
                                (self.stats['name'], h.encode('hex')))
            self.table[h] -= 1
            if self.table[h] <= 0:
                del self.table[h]
        self.stats['size'] = len(self.table)
        logging.info('%(name)s: Trimmed from %(oldsize)s to %(size)s' \
                     % self.stats)
        self.stats['nexttrim'] = \
                    pyclean.timing.future(secs=self.stats['timedtrim'])

    def statlog(self):
        """Log details of the EMP hash."""
        self.stats['size'] = len(self.table)
        logmes = '%(name)s: size=%(size)s, '
        logmes += 'processed=%(processed)s, accepted=%(accepted)s, '
        logmes += 'rejected=%(rejected)s'
        logging.info(logmes % self.stats)


if (__name__ == "__main__"):
    import random
    emp = EMP(threshold=2,
              dofuzzy=True,
              name='emp_test')
    iters = 0
    while iters < 50000:
        randstring = ""
        while len(randstring) < 3:
            randstring += random.choice('abcdefghijklmnopqrstuvwxyz')
        randstring += 'xxxxxxxxxx'
        if iters % 1000 == 0:
            sys.stdout.write('Doing iteration %s\n' % iters)
        if emp.add(randstring):
            pass
            #sys.stdout.write('Collision on %s\n' % randstring)
        iters += 1
