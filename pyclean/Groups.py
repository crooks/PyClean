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

import re
import logging
from collections import defaultdict

class Groups():
    def __init__(self):
        self.regex = Regex()

    def __getitem__(self, grptest):
        return self.grp[grptest]

    def __contains__(self, item):
        if item in self.grp:
            return True
        return False

    def analyze(self, newsgroups):
        self.grp = defaultdict(lambda: 0)
        nglist = str(newsgroups).split(',')
        nglen = len(nglist)
        for ng in nglist:
            if self.regex.test.search(ng):
                self.grp['test'] += 1
            if self.regex.bin_allowed.search(ng):
                self.grp['bin_allowed'] += 1
            if self.regex.emp_exclude.search(ng):
                self.grp['emp_exclude'] += 1
            if self.regex.ihn_exclude.search(ng):
                self.grp['ihn_exclude'] += 1
            if self.regex.bin_allowed.search(ng):
                self.grp['html_allowed'] += 1
        # Not all bools will be meaningful but it's easier to create them
        # generically then specifically.
        for ngelement in self.grp.keys():
            ngbool = '%s_bool' % ngelement
            self.grp[ngbool] = self.grp[ngelement] == nglen

class Regex():
    def __init__(self):
        # Test groups
        test =  ['\.test(ing)?(?:$|\.)',
                 '^es\.pruebas',
                 '^borland\.public\.test2',
                 '^cern\.testnews']
        self.test = self.regex_compile(test)
        # Binary groups
        bin_allowed = ['^bin[a.]','\.bin[aei.]','\.bin$','^fur\.artwork',
                       '^alt\.anonymous\.messages$','^de\.alt\.dateien',
                       '^rec\.games\.bolo$','^comp\.security\.pgp\.test$',
                       '^sfnet\.tiedostot','^fido\.','^unidata\.',
                       '^alt\.security\.keydist','^linux\.debian\.bugs\.dist$',
                       '^lucky\.freebsd']
        self.bin_allowed = self.regex_compile(bin_allowed)
        html_allowed = ['^pgsql\.', '^relcom\.', '^gmane', 'microsoft']
        self.html_allowed = self.regex_compile(html_allowed)
        # Exclude from all EMP filters
        emp_exclude = ['alt\.anonymous\.messages']
        self.emp_exclude = self.regex_compile(emp_exclude)
        # Exclude groups from IHN filter
        ihn_exclude = ['alt\.anonymous', 'alt\.privacy']
        self.ihn_exclude = self.regex_compile(ihn_exclude)
        # Bad posting-hosts
        bad_ph = ['newsguy\.com','tornevall\.net']
        self.bad_ph = self.regex_compile(bad_ph)

    def regex_compile(self, regexlist):
        textual = '|'.join(regexlist).replace('||', '|')
        return re.compile(textual)

if (__name__ == "__main__"):
    groups = Groups()
    newsgroups = 'alt.test,alt.testing.testing,alt.binaries.foo'
    groups.analyze(newsgroups)
    print groups['test_bool']
    print groups['bin_allowed']
    print groups['bin_allowed_bool']

