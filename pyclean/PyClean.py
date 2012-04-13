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

from Config import config
import emp
import Groups
import timing

import re
import os.path
import logging
import logging.handlers
import sys


def init_logging():
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    logging.getLogger().setLevel(logging.DEBUG)
    logfile = logging.handlers.TimedRotatingFileHandler(
                    os.path.join(config.get('paths', 'log'), 'pyclean.log'),
                    when='midnight',
                    interval=1,
                    backupCount=config.getint('logging', 'retain'),
                    utc=True)
    logfile.setLevel(loglevels[config.get('logging', 'level')])
    logfile.setFormatter(logging.Formatter(logfmt, datefmt=datefmt))
    logging.getLogger().addHandler(logfile)

##  The built-in intern() method has been in the sys module
##  since Python 3.0.
if sys.version_info[0] >= 3:
    def intern(headerName):
        return sys.intern(headerName)

##  This looks weird, but creating and interning these strings should
##  let us get faster access to header keys (which innd also interns) by
##  losing some strcmps under the covers.
Also_Control = intern("Also-Control")
Approved = intern("Approved")
Archive = intern("Archive")
Archived_At = intern("Archived-At")
Bytes = intern("Bytes")
Cancel_Key = intern("Cancel-Key")
Cancel_Lock = intern("Cancel-Lock")
Comments = intern("Comments")
Content_Base = intern("Content-Base")
Content_Disposition = intern("Content-Disposition")
Content_Transfer_Encoding = intern("Content-Transfer-Encoding")
Content_Type = intern("Content-Type")
Control = intern("Control")
Date = intern("Date")
Date_Received = intern("Date-Received")
Distribution = intern("Distribution")
Expires = intern("Expires")
Face = intern("Face")
Followup_To = intern("Followup-To")
From = intern("From")
In_Reply_To = intern("In-Reply-To")
Injection_Date = intern("Injection-Date")
Injection_Info = intern("Injection-Info")
Keywords = intern("Keywords")
Lines = intern("Lines")
List_ID = intern("List-ID")
Message_ID = intern("Message-ID")
MIME_Version = intern("MIME-Version")
Newsgroups = intern("Newsgroups")
NNTP_Posting_Date = intern("NNTP-Posting-Date")
NNTP_Posting_Host = intern("NNTP-Posting-Host")
NNTP_Posting_Path  = intern("NNTP-Posting-Path")
Organization = intern("Organization")
Original_Sender = intern("Original-Sender")
Originator = intern("Originator")
Path = intern("Path")
Posted = intern("Posted")
Posting_Version = intern("Posting-Version")
Received = intern("Received")
References = intern("References")
Relay_Version = intern("Relay-Version")
Reply_To = intern("Reply-To")
Sender = intern("Sender")
Subject = intern("Subject")
Summary = intern("Summary")
Supersedes = intern("Supersedes")
User_Agent = intern("User-Agent")
X_Auth = intern("X-Auth")
X_Auth_Sender = intern("X-Auth-Sender")
X_Canceled_By = intern("X-Canceled-By")
X_Cancelled_By = intern("X-Cancelled-By")
X_Complaints_To = intern("X-Complaints-To")
X_Face = intern("X-Face")
X_HTTP_UserAgent = intern("X-HTTP-UserAgent")
X_HTTP_Via = intern("X-HTTP-Via")
X_Mailer = intern("X-Mailer")
X_Modbot = intern("X-Modbot")
X_Modtrace = intern("X-Modtrace")
X_Newsposter = intern("X-Newsposter")
X_Newsreader = intern("X-Newsreader")
X_No_Archive = intern("X-No-Archive")
X_Original_Message_ID = intern("X-Original-Message-ID")
X_Original_NNTP_Posting_Host = intern("X-Original-NNTP-Posting-Host")
X_Original_Trace = intern("X-Original-Trace")
X_Originating_IP = intern("X-Originating-IP")
X_PGP_Key = intern("X-PGP-Key")
X_PGP_Sig = intern("X-PGP-Sig")
X_Poster_Trace = intern("X-Poster-Trace")
X_Postfilter = intern("X-Postfilter")
X_Proxy_User = intern("X-Proxy-User")
X_Submissions_To = intern("X-Submissions-To")
X_Trace = intern("X-Trace")
X_Usenet_Provider = intern("X-Usenet-Provider")
X_User_ID = intern("X-User-ID")
Xref = intern("Xref")
__BODY__ = intern("__BODY__")
__LINES__ = intern("__LINES__")

class pyclean():
    def __init__(self):
        """This runs every time the filter is loaded or reloaded.
        This is a good place to initialize variables and precompile
        regular expressions, or maybe reload stats from disk.

        """
        logdir = config.get('paths', 'log')
        self.logdir = logdir

        # Initialize Group Analizer
        self.groups = Groups.Groups()

        self.regex_ph = re.compile('posting-host *= *"?([^";]+)')

        # Set up the EMP filters
        self.emp_body = emp.EMP(dofuzzy=True, name='emp_body')
        self.emp_phn = emp.EMP(name='emp_phn')
        self.emp_phl = emp.EMP(name='emp.phl')
        self.emp_fsl = emp.EMP(name='emp_fsl')

        # Initialize bad_ Regular Expressions
        self.timed_events()

    def filter(self, art):
        # Trigger timed reloads
        if timing.now() > self.timed_reload:
            self.timed_events()

        # Try to establish the posting host
        ph = None
        logging.debug('Injection-Info: %s' % art[Injection_Info])
        if art[Injection_Info] is not None:
            isph = self.regex_ph.search(art[Injection_Info])
            if isph:
                ph = isph.group(1)
        if ph is None and art[NNTP_Posting_Host] is not None:
            ph = str(art[NNTP_Posting_Host])
        # Ascertain if this posting-host is meaningful
        if ph is not None:
            bad_ph = self.groups.regex.bad_ph.search(ph)
        else:
            bad_ph = False

        # Compare headers against bad_ files
        if self.bad_groups:
            bg_result = self.bad_groups.search(art[Newsgroups])
            if bg_result:
                return self.reject("Bad Group (%s)" % bg_result.group(0),
                                   art)
        if self.bad_from:
            bf_result = self.bad_from.search(art[From])
            if bf_result:
                return self.reject("Bad From (%s)" % bf_result.group(0),
                                   art)
        if ph and not bad_ph and self.bad_posthost:
            bp_result = self.bad_posthost.search(ph)
            if bp_result:
                return self.reject("Bad Posting-Host (%s)" % \
                                   bp_result.group(0), art)

        # Analyze the Newsgroups header
        self.groups.analyze(art[Newsgroups])

        # Beginning of EMP Body filter
        if not self.groups['emp_exclude_bool']:
            if art[__BODY__] is not None:
                if self.emp_body.add(art[__BODY__]):
                    return self.reject("EMP Body Reject", art)
            if ph is not None:
                # Beginning of PHN filter
                if self.emp_phn.add(ph + str(art[Newsgroups])):
                    return self.reject("EMP PHN Reject", art)
                # Beginning of PHL filter
                if self.emp_phl.add(ph + str(art[__LINES__])):
                    return self.reject("EMP PHL Reject", art)
            # Beginning of FSL filter
            fsl = str(art[From]) + str(art[Subject]) + str(art[__LINES__])
            if self.emp_fsl.add(fsl):
                return self.reject("EMP FSL Reject", art)
        # The article passed all checks. Return an empty string.
        return ""

    def reject(self, reason, art):
        if reason.startswith('EMP PHN'):
            self.logart(reason, art, 'emp.phn')
        if reason.startswith('EMP PHL'):
            self.logart(reason, art, 'emp.phl')
        if reason.startswith('EMP FSL'):
            self.logart(reason, art, 'emp.fsl')
        if reason.startswith('EMP Body'):
            self.logart(reason, art, 'emp.body')
        if reason.startswith('Bad'):
            self.logart(reason, art, 'bad_files')
        return reason

    def logart(self, reason, art, filename):
        f = open(os.path.join(self.logdir, filename), 'a')
        f.write('From foo@bar Thu Jan  1 00:00:01 1970\n')
        f.write('Info: %s\n' % reason)
        for hdr in art.keys():
            if hdr == '__BODY__' or hdr == '__LINES__' or art[hdr] is None:
                continue
            f.write('%s: %s\n' % (hdr, art[hdr]))
        f.write('\n')
        f.write(art[__BODY__])
        f.write('\n\n')
        f.close

    def timed_events(self):
        logging.info('Performing timed events')
        self.emp_body.statlog()
        self.emp_fsl.statlog()
        self.emp_phl.statlog()
        self.emp_phn.statlog()
        # Set up bad_ Regular Expressions
        logging.debug('Compiling bad_groups regex')
        self.bad_groups = self.badfile('bad_groups')
        logging.debug('Compiling bad_from regex')
        self.bad_from = self.badfile('bad_from')
        logging.debug('Compiling bad_posthost regex')
        self.bad_posthost = self.badfile('bad_posthost')
        self.timed_reload = timing.future(hours=1)

    def badfile(self, filename):
        """Read a given file and return a regular expression composed of
        individual regex's on each line that have not yet expired.

        """
        fqfn = os.path.join(config.get('paths', 'etc'), filename)
        if not os.path.isfile(fqfn):
            logging.debug('%s: Bad file not found' % filename)
            return False
        # Make a local datetime object for now, just to save setting now in
        # the coming loop.
        now = timing.now()
        # Match lines formated /regex/ timestamp(YYYYMMDD)
        entry = re.compile('/(.+)/[ \t]+(\d{8})')
        bad_items = []
        f = open(fqfn, 'r')
        for line in f:
            valid = entry.match(line)
            if valid:
                try:
                    # Is current time beyond that of the datestamp? If it is,
                    # the entry is considered expired and processing moves to
                    # the next entry.
                    if now > timing.dateobj(valid.group(2)):
                        continue
                except ValueError:
                    # If the timestamp is invalid, just ignore the entry
                    continue
                # If processing gets here, the entry is a valid regex.
                bad_items.append(valid.group(1))
        f.close()
        if len(bad_items) == 0:
            # No valid entires exist in the file.
            logging.debug('%s: No valid entries found' % filename)
            return False
        regex = '|'.join(bad_items)
        # This should never happen but best to check as || will match everything.
        regex = regex.replace('||', '|')
        return re.compile(regex)

init_logging()
