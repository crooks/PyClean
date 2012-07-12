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

from pyclean.Config import config
import pyclean.emp
import pyclean.Groups
import pyclean.timing

import re
import os.path
import logging
import logging.handlers
import sys
import email.utils


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
NNTP_Posting_Path = intern("NNTP-Posting-Path")
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


class Binary():
    def __init__(self):
        # Binaries
        self.regex_yenc = re.compile('^=ybegin.*', re.M)
        self.regex_uuenc = re.compile('^begin[ \t]+0\d{3}[ \t]', re.M)
        self.regex_base64 = re.compile('[a-zA-Z0-9+/]{59,76}[ \t]*$')
        self.regex_binary = re.compile('[ \t]*\S{40,}[ \t]*$')
        # Feedhosts keeps a tally of how many binary articles are received
        # from each upstream peer.
        self.feedhosts = {}

    def increment(self, pathhost):
        """Increment feedhosts."""
        if pathhost in self.feedhosts:
            self.feedhosts[pathhost] += 1
        else:
            self.feedhosts[pathhost] = 1

    def report(self):
        fn = os.path.join(config.get('paths', 'log'), 'binfeeds')
        f = open(fn, 'w')
        f.write('# Binary feeders report - %s\n\n' % \
                                            pyclean.timing.nowstamp())
        for e in self.feedhosts.keys():
            f.write('%s: %s\n' % (e, self.feedhosts[e]))
        f.close()
        self.feedhosts = {}

    def isbin(self, art):
        """The primary function of the Binary class.  An article's body is
        compared against a number of checks.  If the conclusion is that the
        payload is binary, the type of binary is returned.  Non-binary content
        will return False.

        """
        # Ignore base64 encoded content.
        if 'base64' in str(art[Content_Transfer_Encoding]).lower():
            return False
        if self.regex_uuenc.search(art[__BODY__]):
            return 'uuEnc'
        yenc = self.regex_yenc.search(art[__BODY__])
        if yenc:
            # Extract the matching line
            l = yenc.group(0)
            if 'line=' in l and 'size=' in l and 'name=' in l:
                return 'yEnc'
        # Avoid costly checks where articles are shorter than the allowed
        # number of binary lines.
        if int(art[__LINES__]) < config.getint('binary', 'lines_allowed'):
            return False
        # Also avoid these costly checks where a References header is present.
        if (art[References] is not None and
          config.getboolean('binary', 'fasttrack_references')):
            return False
        # Base64 and suspect binary matching
        b64match = 0
        suspect = 0
        for line in str(art[__BODY__]).split('\n'):
            if (line.startswith('-----BEGIN PGP') and
                config.getboolean('binary', 'allow_pgp')):
                break
            if self.regex_base64.match(line):
                b64match += 1
            else:
                b64match = 0
            if self.regex_binary.match(line):
                suspect += 1
            else:
                suspect = 0
            if b64match > config.get('binary', 'lines_allowed'):
                return 'base64'
            if suspect > config.get('binary', 'lines_allowed'):
                if config.getboolean('binary', 'reject_suspected'):
                    return 'binary'
                else:
                    logging.info('Suspect binary: %s' % art[Message_ID])
                break
        return False

class Filter():
    def __init__(self):
        """This runs every time the filter is loaded or reloaded.
        This is a good place to initialize variables and precompile
        regular expressions, or maybe reload stats from disk.

        """

        # Initialize Group Analizer
        self.groups = pyclean.Groups.Groups()
        # Initialize Binary Filters
        self.binary = Binary()

        # Initialize the AUK posters log
        self.batchlog_auk = BatchLog(100, "auklog")

        # Posting Host and Posting Account
        self.regex_ph = re.compile('posting-host *= *"?([^";]+)')
        self.regex_pa = re.compile('posting-account *= *"?([^";]+)')
        # Match lines in bad_files formated /regex/ timestamp(YYYYMMDD)
        self.regex_bads = re.compile('/(.+)/[ \t]+(\d{8})')
        # Hostname - Not a 100% perfect regex but probably good enough.
        hostname1 = '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]+[a-zA-Z0-9])'
        hostname2 = '(\.[a-zA-Z0-9\-]+)+'
        self.regex_hostname = re.compile(hostname1 + hostname2)
        # Path replacement regexs
        self.regex_path1 = re.compile('(![^\.]+)+$')  # Strip RH non-FQDNs
        self.regex_path2 = re.compile('\.POSTED[^!]*$')  # Strip POSTED
        self.regex_path3 = re.compile('.*!')  # Strip all but RH path entry
        # Match email addresses
        self.regex_email = \
                re.compile('([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
        # Colon/Space seperated fields
        self.regex_fields = re.compile('[ \t]*([^:]+):[ \t]+(\S+)')
        # Redundant control message types
        self.redundant_controls = ['sendsys', 'senduuname', 'version',
                                   'whogets']

        # Set up the EMP filters
        self.emp_body = pyclean.emp.EMP(name='emp_body',
                            threshold=config.getint('emp', 'body_threshold'),
                            ceiling=config.getint('emp', 'body_ceiling'),
                            maxentries=config.getint('emp', 'body_maxentries'),
                            timedtrim=config.getint('emp', 'body_timed_trim'),
                            dofuzzy=config.getboolean('emp', 'body_fuzzy'))
        self.emp_phn = pyclean.emp.EMP(name='emp_phn',
                            threshold=config.getint('emp', 'phn_threshold'),
                            ceiling=config.getint('emp', 'phn_ceiling'),
                            maxentries=config.getint('emp', 'phn_maxentries'),
                            timedtrim=config.getint('emp', 'phn_timed_trim'))
        self.emp_phl = pyclean.emp.EMP(name='emp.phl',
                            threshold=config.getint('emp', 'phl_threshold'),
                            ceiling=config.getint('emp', 'phl_ceiling'),
                            maxentries=config.getint('emp', 'phl_maxentries'),
                            timedtrim=config.getint('emp', 'phl_timed_trim'))
        self.emp_fsl = pyclean.emp.EMP(name='emp_fsl',
                            threshold=config.getint('emp', 'fsl_threshold'),
                            ceiling=config.getint('emp', 'fsl_ceiling'),
                            maxentries=config.getint('emp', 'fsl_maxentries'),
                            timedtrim=config.getint('emp', 'fsl_timed_trim'))
        self.emp_ihn = pyclean.emp.EMP(name='emp_ihn',
                            threshold=config.getint('emp', 'ihn_threshold'),
                            ceiling=config.getint('emp', 'ihn_ceiling'),
                            maxentries=config.getint('emp', 'ihn_maxentries'),
                            timedtrim=config.getint('emp', 'ihn_timed_trim'))

        # Initialize timed events
        self.hourly_events(startup=True)
        # Set a datetime object for next midnight
        self.midnight_trigger = pyclean.timing.next_midnight()

    def filter(self, art):
        # Initialize the posting info dict
        post = {}

        # Trigger timed reloads
        now = pyclean.timing.now()
        if now > self.hourly_trigger:
            self.hourly_events()
        if now > self.midnight_trigger:
            self.midnight_events()

        # Attempt to split the From address into component parts
        if 'From' in art:
            post['from_name'], \
            post['from_email'] = email.utils.parseaddr(art['From'])

        # Try to establish the injection-host, posting-host and
        # posting-account
        if art[Injection_Info] is not None:
            # Establish Posting Account
            ispa = self.regex_pa.search(art[Injection_Info])
            if ispa:
                post['posting-account'] = ispa.group(1)
            # Establish Posting Host
            isph = self.regex_ph.search(art[Injection_Info])
            if isph:
                post['posting-host'] = isph.group(1)
            # Establish injection host
            isih = self.regex_hostname.match(art[Injection_Info])
            if isih:
                post['injection-host'] = isih.group(0)

        # posting-host might be obtainable from NNTP-Posting-Host
        if not 'posting-host' in post and art[NNTP_Posting_Host] is not None:
            post['posting-host'] = str(art[NNTP_Posting_Host])

        # If the injection-host wasn't found in Injection-Info, try the
        # X-Trace header
        if not 'injection-host' in post and art[X_Trace] is not None:
            isih = self.regex_hostname.search(art[X_Trace])
            if isih:
                post['injection-host'] = isih.group(0)
                #logging.debug('Injection-Host (from XT): %s' % ih)

        # Try to extract a hostname from the Path header
        if (not 'injection-host' in post and
          config.getboolean('hostnames', 'path_hostname')):
            sub1 = re.sub(self.regex_path1, '', art[Path])
            sub2 = re.sub(self.regex_path2, '', sub1)
            sub3 = re.sub(self.regex_path3, '', sub2)
            if self.regex_hostname.match(sub3):
                post['injection-host'] = sub3

        # Special case for Google who use loads of injection-hosts
        if ('injection-host' in post and
          post['injection-host'].endswith('googlegroups.com')):
            post['injection-host'] = 'googlegroups.com'
        # Jobcircle use numerous posting hosts, perhaps to circumvent EMP?
        if ('posting-host' in post and
          post['posting-host'].endswith('jobcircle.com')):
            post['posting-host'] = 'jobcircle.com'

        # Ascertain if the posting-host is meaningful
        if 'posting-host' in post:
            #logging.debug('Posting-Host: %s' % ph)
            isbad_ph = self.groups.regex.bad_ph.search(post['posting-host'])
            if isbad_ph:
                post['bad-posting-host'] = isbad_ph.group(0)
                logging.debug('Bad posting host: %s' % \
                              post['bad-posting-host'])

        # The host that fed us this article is first in the Path header.
        post['feed-host'] = str(art[Path]).split('!', 1)[0]

        # Analyze the Newsgroups header
        self.groups.analyze(art[Newsgroups])

        ## --- Everything below is accept / reject code ---

        #TODO Control message handling still needs to be written
        if art[Control] is not None:
            ctrltype = str(art[Control]).split(" ", 1)[0]
            # Reject control messages with supersedes headers
            if art[Supersedes] is not None:
                return reject('Control %s with Supersedes header' % ctrltype,
                              art, post)
            if (ctrltype == 'cancel' and
              config.getboolean('control', 'reject_cancels')):
                return self.reject("Control cancel", art, post)
            elif (ctrltype in self.redundant_controls and
              config.getboolean('control', 'reject_redundant')):
                return reject("Redundant Control Type: %s" % ctrltype)
            else:
                logging.info('Control: %s, mid=%s' % (art[Control],
                                                      art[Message_ID]))
            return ''

        # Max-crosspost check
        if self.groups['count'] > config.get('groups', 'max_crosspost'):
            return self.reject("Crosspost Limit Exceeded", art, post)

        # Lines check
        if art[Lines] and int(art[Lines]) != int(art[__LINES__]):
            logmes = "Lines Mismatch: Header=%s, INN=%s, mid=%s"
            if art[User_Agent] is not None:
                logmes += ", Agent=%s"
                logging.debug(logmes % (art[Lines], art[__LINES__],
                                        art[Message_ID], art[User_Agent]))
            else:
                logging.debug(logmes % (art[Lines], art[__LINES__],
                                        art[Message_ID]))

        # Newsguy are evil sex spammers
        if (art[Message_ID] and 'newsguy.com' in str(art[Message_ID]) and
            config.getboolean('filters', 'newsguy') and
            'alt.sex' in str(art[Newsgroups])):
            return self.reject("Newsguy Sex", art, post)

        # For some reason, this OS2 group has become kook central
        if (art[Newsgroups] and
            'comp.os.os2.advocacy' in str(art[Newsgroups]) and
            self.groups['count'] > 1):
            return self.reject("OS2 Crosspost", art, post)
        if (art[Followup_To] and
            'comp.os.os2.advocacy' in str(art[Followup_To])):
            return self.reject("OS2 Followup", art, post)

        # Compare headers against regex files
        if self.log_from:
            lf_result = self.log_from.search(art[From])
            if lf_result:
                self.logart(lf_result.group(0), art, post, 'log_from',
                            trim=False)
        if self.bad_groups:
            bg_result = self.bad_groups.search(art[Newsgroups])
            if bg_result:
                return self.reject("Bad Group (%s)" % bg_result.group(0),
                                   art, post)
        if self.bad_from:
            bf_result = self.bad_from.search(art[From])
            if bf_result:
                return self.reject("Bad From (%s)" % bf_result.group(0),
                                   art, post)
        if self.bad_body:
            bb_result = self.bad_body.search(art[__BODY__])
            if bb_result:
                return self.reject("Bad Body (%s)" % bb_result.group(0),
                                   art, post)
        if ('posting-host' in post and
            not 'bad_posting-host' in post and self.bad_posthost):
            bp_result = self.bad_posthost.search(post['posting-host'])
            if bp_result:
                return self.reject("Bad Posting-Host (%s)" % \
                                   bp_result.group(0), art, post)

        # Is the source of the post considered local?
        if ('injection-host' in post and self.local_hosts and
          self.local_hosts.search(post['injection-host'])):
            self.logart('Local Post', art, post, 'local_post')
            # Local Bad From
            if self.local_bad_from:
                bf_result = self.local_bad_from.search(art[From])
                if bf_result:
                    return self.reject("Local Bad From (%s)" % \
                                       bf_result.group(0), art, post)
            # Local Bad Groups
            if self.local_bad_groups:
                bg_result = self.local_bad_groups.search(art[Newsgroups])
                if bg_result:
                    return self.reject("Local Bad Group (%s)" % \
                                       bg_result.group(0), art, post)

        # Misplaced binary check
        isbin = self.binary.isbin(art)
        if config.getboolean('binary', 'reject_all') and isbin:
            self.binary.increment(post['feed-host'])
            return self.reject("Binary (%s)" % isbin, art, post)
        elif not self.groups['binary_allowed_bool'] and isbin:
            self.binary.increment(post['feed-host'])
            return self.reject("Binary Misplaced (%s)" % isbin, art, post)
        # Misplaced HTML check
        if (not self.groups['html_allowed_bool'] and
          config.getboolean('filters', 'reject_html') and
          art[Content_Type] is not None):
            if 'text/html' in str(art[Content_Type]).lower():
                return self.reject("HTML Misplaced", art, post)
            if 'multipart' in art[Content_Type]:
                if config.getboolean('filters', 'reject_multipart'):
                    return self.reject("MIME Multpart", art, post)
                else:
                    logging.info('Multipart: %s' % art[Message_ID])

        # Start of EMP checks
        if (not self.groups['emp_exclude_bool'] and
            not self.groups['test_bool']):
            # Create a sorted Newsgroups header to prevent reordering to
            # circumvent EMP.
            ngs = ','.join(sorted(str(art[Newsgroups]).lower().split(',')))
            # Start of posting-host based checks.
            # First try and seed some filter fodder.
            if 'posting-account' in post:
                # If a Posting-Account is known, it makes better filter fodder
                # than the hostname/address which could be dynamic.
                fodder = post['posting-account']
            elif 'bad-posting-host' in post:
                # If we can't trust the info in posting-host, use the
                # injection-host. This is a worst-case scenario.
                if ('injection-host' in post and
                    config.getboolean('emp', 'ph_coarse')):
                    fodder = post['injection-host']
                else:
                    fodder = None
            elif 'posting-host' in post:
                fodder = post['posting-host']
            else:
                fodder = None
            if fodder:
                # Beginning of PHN filter
                if self.emp_phn.add(fodder + ngs):
                    return self.reject("EMP PHN Reject", art, post)
                # Beginning of PHL filter
                if self.emp_phl.add(fodder + str(art[__LINES__])):
                    return self.reject("EMP PHL Reject", art, post)
            # Beginning of FSL filter
            fsl = str(art[From]) + str(art[Subject]) + str(art[__LINES__])
            if self.emp_fsl.add(fsl):
                return self.reject("EMP FSL Reject", art, post)
            # Beginning of IHN filter
            if ('injection-host' in post and
                not self.groups['ihn_exclude_bool']):
                ihn_result = self.ihn_hosts.search(post['injection-host'])
                if (ihn_result and
                  self.emp_ihn.add(post['injection-host'] + ngs)):
                    return self.reject("EMP IHN Reject", art, post)
            # Beginning of EMP Body filter.  Do this last, it's most
            # expensive in terms of processing.
            if art[__BODY__] is not None:
                if self.emp_body.add(art[__BODY__]):
                    return self.reject("EMP Body Reject", art, post)

        # Filtering complete, here are some post-filter actions.
        if (self.groups['auk_bool'] and 'injection-host' in post:
            if post['from_email']:
                self.batchlog_auk.add("%s\t%s\t%s"
                                      % (pyclean.timing.today(),
                                         post['from_email'],
                                         post['injection-host']))
                    
        # The article passed all checks. Return an empty string.
        return ""

    def reject(self, reason, art, post):
        for logrule in self.log_rules.keys():
            if reason.startswith(logrule):
                self.logart(reason, art, post, self.log_rules[logrule])
                break
        logging.debug("reject: mid=%s, reason=%s" % (art[Message_ID], reason))
        return reason

    def logart(self, reason, art, post, filename, trim=True):
        f = open(os.path.join(config.get('paths', 'logart'), filename), 'a')
        f.write('From foo@bar Thu Jan  1 00:00:01 1970\n')
        f.write('Info: %s\n' % reason)
        for hdr in art.keys():
            if hdr == '__BODY__' or hdr == '__LINES__' or art[hdr] is None:
                continue
            f.write('%s: %s\n' % (hdr, art[hdr]))
        for hdr in post.keys():
            f.write('%s: %s\n' % (hdr, post[hdr]))
        f.write('\n')
        if (not trim or
          art[__LINES__] <= config.get('logging', 'logart_maxlines')):
            f.write(art[__BODY__])
        else:
            for line in str(art[__BODY__]).split('\n',
                        config.get('logging', 'logart_maxlines'))[:-1]:
                f.write(line + "\n")
            f.write('[snip]')
        f.write('\n\n')
        f.close

    def hourly_events(self, startup=False):
        """Carry out hourly events.  Some of these events may be to check if
        it's time to do other, less frequent events.  Timed events are also
        triggered on startup.  The "startup" flag enables special handling of
        this instance.

        """
        logging.debug('Performing timed events')
        self.emp_body.statlog()
        self.emp_fsl.statlog()
        self.emp_phl.statlog()
        self.emp_phn.statlog()
        self.emp_ihn.statlog()
        # Reload logging directives
        logging.debug('Reloading logging directives')
        self.log_rules = self.file2dict('log_rules')
        # Set up Regular Expressions
        logging.debug('Compiling bad_from regex')
        self.bad_from = self.regex_file('bad_from')
        logging.debug('Compiling bad_groups regex')
        self.bad_groups = self.regex_file('bad_groups')
        logging.debug('Compiling bad_posthost regex')
        self.bad_posthost = self.regex_file('bad_posthost')
        logging.debug('Compiling bad_body regex')
        self.bad_body = self.regex_file('bad_body')
        logging.debug('Compiling ihn_hosts regex')
        self.ihn_hosts = self.regex_file('ihn_hosts')
        logging.debug('Compiling local_hosts regex')
        self.local_hosts = self.regex_file('local_hosts')
        logging.debug('Compiling local_bad_from regex')
        self.local_bad_from = self.regex_file('local_bad_from')
        logging.debug('Compiling local_bad_groups regex')
        self.local_bad_groups = self.regex_file('local_bad_groups')
        logging.debug('Compiling log_from regex')
        self.log_from = self.regex_file('log_from')
        if not startup:
            # Re-read the config file.
            configfile = os.path.join(config.get('paths', 'etc'),
                                                 'pyclean.cfg')
            logging.info("Reloading config file: %s" % configfile)
            if os.path.isfile(configfile):
                config.read(configfile)
            else:
                logging.warn("%s: File not found" % configfile)
        # Reset the next timed trigger.
        self.hourly_trigger = pyclean.timing.future(hours=1)

    def midnight_events(self):
        """Events that need to occur at midnight each day.

        """
        self.binary.report()
        self.emp_body.reset()
        self.emp_fsl.reset()
        self.emp_phl.reset()
        self.emp_phn.reset()
        self.emp_ihn.reset()
        # Set the midnight trigger for next day.
        self.midnight_trigger = pyclean.timing.next_midnight()

    def regex_file(self, filename):
        """Read a given file and return a regular expression composed of
        individual regex's on each line that have not yet expired.

        """
        fqfn = os.path.join(config.get('paths', 'etc'), filename)
        if not os.path.isfile(fqfn):
            logging.debug('%s: Bad file not found' % filename)
            return False
        # Make a local datetime object for now, just to save setting now in
        # the coming loop.
        now = pyclean.timing.now()
        bad_items = []
        f = open(fqfn, 'r')
        for line in f:
            valid = self.regex_bads.match(line)
            if valid:
                try:
                    # Is current time beyond that of the datestamp? If it is,
                    # the entry is considered expired and processing moves to
                    # the next entry.
                    if now > pyclean.timing.dateobj(valid.group(2)):
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
        # This should never happen but best to check as || will match
        # everything.
        regex = regex.replace('||', '|')
        return re.compile(regex)

    def file2list(self, filename):
        fqfn = os.path.join(config.get('paths', 'etc'), filename)
        if not os.path.isfile(fqfn):
            logging.info('%s: File not found' % filename)
            return []
        f = open(fqfn, 'r')
        lines = f.readlines()
        f.close()
        valid = []
        for line in lines:
            # Strip comments (including inline)
            content = line.split('#', 1)[0].strip()
            # Ignore empty lines
            if len(content) > 0:
                valid.append(content)
        return valid

    def file2dict(self, filename, numeric=False):
        """Read a file and split each line at the first space encountered. The
        first element is the key, the rest is the content. If numeric is True
        then only integer values will be acccepted."""
        d = {}
        for line in self.file2list(filename):
            valid = self.regex_fields.match(line)
            if valid:
                k = valid.group(1)
                c = valid.group(2)
                if numeric:
                    try:
                        c = int(c)
                    except ValueError:
                        c = 0
                d[k] = c
        return d

    def closetasks(self):
        """Things to do on filter closing.

        """
        logging.info("Running shutdown tasks")
        # Write to file any entries in the stack
        self.batchlog_auk.stack_write()


class BatchLog():
    """This class stacks up log-type entries until a predefined limit is
    reached.  At that point it writes them to a file and starts again.

    """
    def __init__(self, stacksize, filename):
        self.stacksize = stacksize
        self.filename = os.path.join(config.get('paths', 'log'), filename)
        # Initialize the stack itself
        self.stack = []

    def stack_write(self):
        f = open(self.filename, 'a')
        for entry in self.stack:
            f.write(entry + "\n")
        logging.info("Batchlog wrote %s entries to %s"
                     % (len(self.stack), self.filename))
        f.close()
        self.stack = []

    def add(self, entry):
        self.stack.append(entry)
        if len(self.stack) > self.stacksize:
            self.stack_write()



init_logging()

if (__name__ == "__main__"):
    test = Filter()
