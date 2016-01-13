# vim: tabstop=4 expandtab shiftwidth=4 autoindent

import INN

import re
import os
import os.path
import traceback
import logging
import logging.handlers
import shelve
import sys
import datetime
import ConfigParser

# In Python2.4, utils was called Utils
try:
    from email.utils import parseaddr
except ImportError:
    from email.Utils import parseaddr

# Python 2.4 doesn't have hashlib
try:
    from hashlib import md5
except ImportError:
    import md5

# First, define some high-level date/time functions
def now():
    return datetime.datetime.utcnow()
    #return datetime.datetime.now()


def timestamp(stamp):
    return stamp.strftime("%Y-%m-%d %H:%M:%S")


def dateobj(datestr):
    """Take a string formated date (yyyymmdd) and return a datetime object."""
    return datetime.datetime.strptime(datestr, '%Y%m%d')


def nowstamp():
    """A shortcut function to return a textual representation of now."""
    return timestamp(now())


def last_midnight():
    return now().replace(hour=0, minute=0, second=0, microsecond=0)


def next_midnight():
    """Return a datetime object relating to the next midnight.

    """
    return last_midnight() + datetime.timedelta(days=1)


def future(days=0, hours=0, mins=0, secs=0):
    return now() + datetime.timedelta(days=days, hours=hours,
                                      minutes=mins, seconds=secs)

# -----This section is concerned with setting up a default configuration

def makedir(d):
    """Check if a given directory exists.  If it doesn't, check if the
    parent exists.  If it does then the new directory will be created.  If
    not then sensible options are exhausted and the program aborts.

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


def init_config():
    # Configure the Config Parser.
    config = ConfigParser.RawConfigParser()

    # Logging
    config.add_section('logging')
    config.set('logging', 'level', 'info')
    config.set('logging',
            'format', '%(asctime)s %(levelname)s %(message)s')
    config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')
    config.set('logging', 'retain', 7)
    config.set('logging', 'logart_maxlines', 20)

    # Binary
    config.add_section('binary')
    config.set('binary', 'lines_allowed', 15)
    config.set('binary', 'allow_pgp', 'true')
    config.set('binary', 'reject_suspected', 'false')
    config.set('binary', 'fasttrack_references', 'true')

    # EMP
    config.add_section('emp')
    config.set('emp', 'ph_coarse', 'true')
    config.set('emp', 'body_threshold', 5)
    config.set('emp', 'body_ceiling', 85)
    config.set('emp', 'body_maxentries', 5000)
    config.set('emp', 'body_timed_trim', 3600)
    config.set('emp', 'body_fuzzy', 'yes')
    config.set('emp', 'phn_threshold', 150)
    config.set('emp', 'phn_ceiling', 200)
    config.set('emp', 'phn_maxentries', 5000)
    config.set('emp', 'phn_timed_trim', 1800)
    config.set('emp', 'phl_threshold', 20)
    config.set('emp', 'phl_ceiling', 80)
    config.set('emp', 'phl_maxentries', 5000)
    config.set('emp', 'phl_timed_trim', 3600)
    config.set('emp', 'fsl_threshold', 20)
    config.set('emp', 'fsl_ceiling', 40)
    config.set('emp', 'fsl_maxentries', 5000)
    config.set('emp', 'fsl_timed_trim', 3600)
    config.set('emp', 'ihn_threshold', 10)
    config.set('emp', 'ihn_ceiling', 15)
    config.set('emp', 'ihn_maxentries', 1000)
    config.set('emp', 'ihn_timed_trim', 7200)

    config.add_section('groups')
    config.set('groups', 'max_crosspost', 10)

    config.add_section('control')
    config.set('control', 'reject_cancels', 'false')
    config.set('control', 'reject_redundant', 'true')

    config.add_section('filters')
    config.set('filters', 'newsguy', 'true')
    config.set('filters', 'reject_html', 'true')
    config.set('filters', 'reject_multipart', 'false')

    config.add_section('hostnames')
    config.set('hostnames', 'path_hostname', 'true')

    # The path section is a bit tricky. First off we try to read a default
    # config file.  This can define the path to everything, including the
    # pyclean.cfg config file.  For this reason, all the path entries that
    # could generate directories need to come after the config files have
    # been read.
    config.add_section('paths')
    # In accordance with Debian standards, we'll look for
    # /etc/default/pyclean.  This file can define the path for pyclean's
    # etc, which includes the pyclean.cfg file.  The location of the
    # default file can be overridden by setting the 'PYCLEAN' environment
    # variable.
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

    if not config.has_option('paths', 'logart'):
        config.set('paths', 'logart', os.path.join(basedir, 'articles'))
    makedir(config.get('paths', 'logart'))

    if not config.has_option('paths', 'lib'):
        config.set('paths', 'lib', os.path.join(basedir, 'lib'))
    makedir(config.get('paths', 'lib'))

    # The following lines can be uncommented in order to write a config
    # file. This is useful for creating an example file.
    #with open('example.cfg', 'wb') as configfile:
    #    config.write(configfile)
    return config


class InndFilter:
    """Provide filtering callbacks to innd."""

    def __init__(self):
        """This runs every time the filter is loaded or reloaded.
        This is a good place to initialize variables and precompile
        regular expressions, or maybe reload stats from disk.

        """
        self.traceback_loop = 0
        try:
            self.pyfilter = Filter()
        except:
            fn = os.path.join(config.get('paths', 'log'), 'init_traceback')
            f = open(fn, 'a')
            traceback.print_exc(file=f)
            f.close()

    def filter_before_reload(self):
        """Runs just before the filter gets reloaded.

        You can use this method to save state information to be
        restored by the __init__() method or down in the main module.
        """
        try:
            self.pyfilter.closetasks()
        except:
            fn = os.path.join(config.get('paths', 'log'), 'close_traceback')
            f = open(fn, 'a')
            traceback.print_exc(file=f)
            f.close()
        return ""

    def filter_close(self):
        """Runs when innd exits.

        You can use this method to save state information to be
        restored by the __init__() method or down in the main module.
        """
        try:
            self.pyfilter.closetasks()
        except:
            fn = os.path.join(config.get('paths', 'log'), 'close_traceback')
            f = open(fn, 'a')
            traceback.print_exc(file=f)
            f.close()
        return ""
        INN.syslog('notice', "filter_close running, bye!")

    def filter_messageid(self, msgid):
        """Filter articles just by their Message-IDs.

        This method interacts with the CHECK, IHAVE and TAKETHIS
        NNTP commands.
        If you return a non-empty string here, the offered article
        will be refused before you ever have to waste any bandwidth
        looking at it (unless TAKETHIS is used before an earlier CHECK).
        Make sure that such a message is properly encoded in UTF-8
        so as to comply with the NNTP protocol.
        """
        return ""               # Deactivate the samples.

    def filter_art(self, art):
        """Decide whether to keep offered articles.

        art is a dictionary with a bunch of headers, the article's
        body, and innd's reckoning of the line count.  Items not
        in the article will have a value of None.

        The available headers are the ones listed near the top of
        innd/art.c.  At this writing, they are:

            Also-Control, Approved, Archive, Archived-At, Bytes, Cancel-Key,
            Cancel-Lock, Content-Base, Content-Disposition,
            Content-Transfer-Encoding, Content-Type, Control, Date,
            Date-Received, Distribution, Expires, Face, Followup-To, From,
            In-Reply-To, Injection-Date, Injection-Info, Keywords, Lines,
            List-ID, Message-ID, MIME-Version, Newsgroups, NNTP-Posting-Date,
            NNTP-Posting-Host, NNTP-Posting-Path, Organization,
            Original-Sender, Originator, Path, Posted, Posting-Version,
            Received, References, Relay-Version, Reply-To, Sender, Subject,
            Summary, Supersedes, User-Agent, X-Auth, X-Auth-Sender,
            X-Canceled-By, X-Cancelled-By, X-Complaints-To, X-Face,
            X-HTTP-UserAgent, X-HTTP-Via, X-Mailer, X-Modbot, X-Modtrace,
            X-Newsposter, X-Newsreader, X-No-Archive, X-Original-Message-ID,
            X-Original-NNTP-Posting-Host, X-Original-Trace, X-Originating-IP,
            X-PGP-Key, X-PGP-Sig, X-Poster-Trace, X-Postfilter, X-Proxy-User,
            X-Submissions-To, X-Trace, X-Usenet-Provider, X-User-ID, Xref.

        The body is the buffer in art[__BODY__] and the INN-reckoned
        line count is held as an integer in art[__LINES__].  (The
        Lines: header is often generated by the poster, and large
        differences can be a good indication of a corrupt article.)

        If you want to keep an article, return None or "".  If you
        want to reject, return a non-empty string.  The rejection
        string will appear in transfer and posting response banners,
        and local posters will see them if their messages are
        rejected (make sure that such a response is properly encoded
        in UTF-8 so as to comply with the NNTP protocol).

        """
        try:
            return self.pyfilter.filter(art)
        except:
            if not self.traceback_loop:
                fn = os.path.join(config.get('paths', 'log'), 'traceback')
                f = open(fn, 'a')
                traceback.print_exc(file=f)
                f.close()
                self.traceback_loop = 1
            return ""

    def filter_mode(self, oldmode, newmode, reason):
        """Capture server events and do something useful.

        When the admin throttles or pauses innd (and lets it go
        again), this method will be called.  oldmode is the state we
        just left, and newmode is where we are going.  reason is
        usually just a comment string.

        The possible values of newmode and oldmode are the five
        strings 'running', 'paused', 'throttled', 'shutdown' and
        'unknown'.  Actually 'unknown' shouldn't happen; it's there
        in case feeping creatures invade innd.
        """
        INN.syslog('n', 'state change from %s to %s - %s'
                        % (oldmode, newmode, reason))


class Binary:
    """Perform binary content checking of articles.

    """
    def __init__(self):
        # Binaries
        self.regex_yenc = re.compile('^=ybegin.*', re.M)
        self.regex_uuenc = re.compile('^begin[ \t]+\d{3,4}[ \t]+\w+\.\w', re.M)
        self.regex_base64 = re.compile('[a-zA-Z0-9+/]{59}')
        self.regex_binary = re.compile('[ \t]*\S{40}')
        # Feedhosts keeps a tally of how many binary articles are received
        # from each upstream peer.
        self.feedhosts = {}
        self.tagged = 0

    def increment(self, pathhost):
        """Increment feedhosts."""
        if pathhost in self.feedhosts:
            self.feedhosts[pathhost] += 1
        else:
            self.feedhosts[pathhost] = 1

    def report(self):
        fn = os.path.join(config.get('paths', 'log'), 'binfeeds')
        f = open(fn, 'w')
        f.write('# Binary feeders report - %s\n\n'
                % nowstamp())
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
        skip_refs = ('References' in art and
                     str(art['References']).startswith('<') and
                     config.getboolean('binary', 'fasttrack_references') and
                     int(art[__LINES__]) > 500)
        if skip_refs:
            return False
        # Base64 and suspect binary matching
        b64match = 0
        suspect = 0
        for line in str(art[__BODY__]).split('\n'):
            skip_pgp = (line.startswith('-----BEGIN PGP')
                        and config.getboolean('binary', 'allow_pgp'))
            if skip_pgp:
                break
            # Resetting the next counter to zero on a non-matching line
            # dictates the counted binary lines must be consecutive.
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
                return 'binary'
        return False


class Filter:
    def __init__(self):
        """This runs every time the filter is loaded or reloaded.
        This is a good place to initialize variables and precompile
        regular expressions, or maybe reload stats from disk.

        """

        # Initialize Group Analizer
        self.groups = Groups()
        # Initialize Binary Filters
        self.binary = Binary()

        # Posting Host and Posting Account
        self.regex_ph = re.compile('posting-host *= *"?([^";]+)')
        self.regex_pa = re.compile('posting-account *= *"?([^";]+)')
        # Match lines in bad_files formated /regex/ timestamp(YYYYMMDD)
        self.regex_bads = re.compile('/(.+)/[ \t]+(\d{8})')

        # A dictionary of files containing regexs that need to be reloaded and
        # compiled if the timestamp on them changes.  The dict content is the
        # timestamp (initially zeroed).
        bad_file_list = ['bad_from', 'bad_groups', 'bad_posthost', 'bad_body',
                         'ihn_hosts', 'local_hosts', 'local_bad_from',
                         'local_bad_groups', 'local_bad_body', 'log_from',
                         'bad_groups_dizum', 'bad_crosspost_host',
                         'bad_cp_groups', 'local_bad_cp_groups']
        # Each bad_file key contains a timestamp of last-modified time.
        # Setting all keys to zero ensures they are processed on first run.
        bad_files = dict((f, 0) for f in bad_file_list)
        # Python >= 2.7 has dict comprehension but not earlier versions
        # bad_files = {f: 0 for f in bad_file_list}
        self.bad_files = bad_files
        # A dict of the regexs compiled from the bad_files defined above.
        self.bad_regexs = {}

        # Hostname - Not a 100% perfect regex but probably good enough.
        self.regex_hostname = re.compile('([a-zA-Z0-9]|[a-zA-Z0-9]'
                                         '[a-zA-Z0-9\-]+[a-zA-Z0-9])'
                                         '(\.[a-zA-Z0-9\-]+)+')
        # Path replacement regexs
        self.regex_pathhost = re.compile('(![^\.]+)+$')  # Strip RH non-FQDNs
        # Match email addresses
        self.regex_email = \
            re.compile('([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
        # Colon/Space seperated fields
        self.regex_fields = re.compile('[ \t]*([^:]+):[ \t]+(\S+)')
        # Content-Type: text/plain; charset=utf-8
        self.regex_ct = re.compile("\s*([^;]+)")
        self.regex_ctcs = re.compile('charset="?([^"\s;]+)')
        # Redundant control message types
        self.redundant_controls = ['sendsys', 'senduuname', 'version',
                                   'whogets']

        # Set up the EMP filters
        self.emp_body = EMP(name='emp_body',
                            threshold=config.getint('emp', 'body_threshold'),
                            ceiling=config.getint('emp', 'body_ceiling'),
                            maxentries=config.getint('emp', 'body_maxentries'),
                            timedtrim=config.getint('emp', 'body_timed_trim'),
                            dofuzzy=config.getboolean('emp', 'body_fuzzy'))
        self.emp_phn = EMP(name='emp_phn',
                           threshold=config.getint('emp', 'phn_threshold'),
                           ceiling=config.getint('emp', 'phn_ceiling'),
                           maxentries=config.getint('emp', 'phn_maxentries'),
                           timedtrim=config.getint('emp', 'phn_timed_trim'))
        self.emp_phl = EMP(name='emp.phl',
                           threshold=config.getint('emp', 'phl_threshold'),
                           ceiling=config.getint('emp', 'phl_ceiling'),
                           maxentries=config.getint('emp', 'phl_maxentries'),
                           timedtrim=config.getint('emp', 'phl_timed_trim'))
        self.emp_fsl = EMP(name='emp_fsl',
                           threshold=config.getint('emp', 'fsl_threshold'),
                           ceiling=config.getint('emp', 'fsl_ceiling'),
                           maxentries=config.getint('emp', 'fsl_maxentries'),
                           timedtrim=config.getint('emp', 'fsl_timed_trim'))
        self.emp_ihn = EMP(name='emp_ihn',
                           threshold=config.getint('emp', 'ihn_threshold'),
                           ceiling=config.getint('emp', 'ihn_ceiling'),
                           maxentries=config.getint('emp', 'ihn_maxentries'),
                           timedtrim=config.getint('emp', 'ihn_timed_trim'))

        # Initialize timed events
        self.hourly_events(startup=True)
        # Set a datetime object for next midnight
        self.midnight_trigger = next_midnight()

    def filter(self, art):
        # Initialize the posting info dict
        post = {}

        # Trigger timed reloads
        if now() > self.hourly_trigger:
            self.hourly_events()
        if now() > self.midnight_trigger:
            self.midnight_events()

        # Attempt to split the From address into component parts
        if 'From' in art:
            post['from_name'], \
                post['from_email'] = parseaddr(art['From'])

        if art[Content_Type] is not None:
            ct = self.regex_ct.match(art[Content_Type])
            if ct:
                post['content_type'] = ct.group(1).lower()
            ctcs = self.regex_ctcs.search(art[Content_Type])
            if ctcs:
                post['charset'] = ctcs.group(1).lower()

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
        if 'posting-host' not in post and art[NNTP_Posting_Host] is not None:
            post['posting-host'] = str(art[NNTP_Posting_Host])

        # If the injection-host wasn't found in Injection-Info, try the X-Trace
        # header.  We only look for a hostname as the first field in X-Trace,
        # otherwise it's regex hell.
        if 'injection-host' not in post and art[X_Trace] is not None:
            isih = self.regex_hostname.match(art[X_Trace])
            if isih:
                post['injection-host'] = isih.group(0)

        # Try to extract a hostname from the Path header
        if config.getboolean('hostnames', 'path_hostname'):
            # First, check for a !.POSTED tag, as per RFC5537
            if 'injection-host' not in post and "!.POSTED" in str(art[Path]):
                postsplit = str(art[Path]).split("!.POSTED", 1)
                pathhost = postsplit[0].split("!")[-1]
                if pathhost:
                    post['injection-host'] = pathhost
            # Last resort, try the right-most entry in the Path header
            if 'injection-host' not in post:
                subhost = re.sub(self.regex_pathhost, '', art[Path])
                pathhost = subhost.split("!")[-1]
                if pathhost:
                    post['injection-host'] = pathhost

        # Some services (like Google) use dozens of Injection Hostnames.
        # This section looks for substring matches and replaces the entire
        # Injection-Host with the substring.
        if 'injection-host' in post:
            for ihsub in self.ihsubs:
                if ihsub in post['injection-host']:
                    logging.debug("Injection-Host: Replacing %s with %s",
                                  post['injection-host'], ihsub)
                    post['injection-host'] = ihsub

        # Ascertain if the posting-host is meaningful
        if 'posting-host' in post:
            isbad_ph = self.groups.regex.bad_ph.search(post['posting-host'])
            if isbad_ph:
                post['bad-posting-host'] = isbad_ph.group(0)
                logging.debug('Bad posting host: %s',
                              post['bad-posting-host'])

        # The host that fed us this article is first in the Path header.
        post['feed-host'] = str(art[Path]).split('!', 1)[0]

        # Analyze the Newsgroups header
        self.groups.analyze(art[Newsgroups])

        # Is the source of the post considered local?
        local = False
        if ('injection-host' in post and
                'local_hosts' in self.bad_regexs and
                self.bad_regexs['local_hosts'].search(post['injection-host'])):
            local = True

        # --- Everything below is accept / reject code ---

        # Reject any messages that don't have a Message-ID
        if Message_ID not in art:
            logging.warn("Wot no Message-ID!  Rejecting message because the "
                         "implications of accepting it are unpredictable.")
            return self.reject("No Message-ID header", art, post)
        # We use Message-ID strings so much, it's useful to have a shortcut.
        mid = str(art[Message_ID])

        # Control message handling
        if art[Control] is not None:
            ctrltype = str(art[Control]).split(" ", 1)[0]
            # Reject control messages with supersedes headers
            if art[Supersedes] is not None:
                return self.reject('Control %s with Supersedes header'
                                   % ctrltype, art, post)
            if (ctrltype == 'cancel' and
                    config.getboolean('control', 'reject_cancels')):
                return self.reject("Control cancel", art, post)
            elif (ctrltype in self.redundant_controls and
                  config.getboolean('control', 'reject_redundant')):
                return self.reject("Redundant Control Type: %s" % ctrltype)
            else:
                logging.info('Control: %s, mid=%s' % (art[Control], mid))
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
                                        mid, art[User_Agent]))
            else:
                logging.debug(logmes % (art[Lines], art[__LINES__], mid))

        # Newsguy are evil sex spammers
        if ('newsguy.com' in mid and
                config.getboolean('filters', 'newsguy') and
                'sex_groups' in self.groups and
                self.groups['sex_groups'] > 0):
            return self.reject("Newsguy Sex", art, post)

        # For some reason, this OS2 group has become kook central
        if ('comp.os.os2.advocacy' in self.groups['groups'] and
                self.groups['count'] > 1):
            return self.reject("OS2 Crosspost", art, post)
        if (art[Followup_To] and
                'comp.os.os2.advocacy' in str(art[Followup_To])):
            return self.reject("OS2 Followup", art, post)

        # Compare headers against regex files

        # Reject these posting-hosts
        if ('posting-host' in post and
                'bad_posting-host' not in post and
                'bad_posthost' in self.bad_regexs):
            bph = self.bad_regexs['bad_posthost'].search(post['posting-host'])
            if bph:
                return self.reject("Bad Posting-Host (%s)"
                                   % bph.group(0), art, post)

        # Test posting-hosts that are not allowed to crosspost
        if ('posting-host' in post and
                self.groups['count'] > 1 and
                'bad_crosspost_host' in self.bad_regexs):
            ph = post['posting-host']
            bph = self.bad_regexs['bad_crosspost_host'].search(ph)
            if bph:
                return self.reject("Bad Crosspost Host (%s)"
                                   % bph.group(0), art, post)

        # Groups where crossposting is not allowed
        if (self.groups['count'] > 1 and
                'bad_cp_groups' in self.bad_regexs):
            bcg = self.bad_regexs['bad_cp_groups'].search(art[Newsgroups])
            if bcg:
                return self.reject("Bad Crosspost Group (%s)"
                                   % bcg.group(0), art, post)

        if 'log_from' in self.bad_regexs:
            lf_result = self.bad_regexs['log_from'].search(art[From])
            if lf_result:
                self.logart(lf_result.group(0), art, post, 'log_from',
                            trim=False)

        if 'bad_groups' in self.bad_regexs:
            bg_result = self.bad_regexs['bad_groups'].search(art[Newsgroups])
            if bg_result:
                return self.reject("Bad Group (%s)" % bg_result.group(0),
                                   art, post)

        if ('injection-host' in post and
                post['injection-host'] == 'sewer.dizum.com' and
                'bad_groups_dizum' in self.bad_regexs):
            bgd = self.bad_regexs['bad_groups_dizum'].search(art[Newsgroups])
            if bgd:
                return self.reject("Bad Dizum Group (%s)"
                                   % bgd.group(0), art, post)

        if 'bad_from' in self.bad_regexs:
            bf_result = self.bad_regexs['bad_from'].search(art[From])
            if bf_result:
                return self.reject("Bad From (%s)" % bf_result.group(0),
                                   art, post)

        if 'bad_body' in self.bad_regexs:
            bb_result = self.bad_regexs['bad_body'].search(art[__BODY__])
            if bb_result:
                return self.reject("Bad Body (%s)" % bb_result.group(0),
                                   art, post)

        # The following checks are for locally posted articles

        # Groups where crossposting is not allowed
        if (local and self.groups['count'] > 1 and
                'local_bad_cp_groups' in self.bad_regexs):
            b = self.bad_regexs['local_bad_cp_groups'].search(art[Newsgroups])
            if b:
                return self.reject("Local Bad Crosspost Group (%s)"
                                   % b.group(0), art, post)

        # Local Bad From
        if local and 'local_bad_from' in self.bad_regexs:
            reg = self.bad_regexs['local_bad_from']
            bf_result = reg.search(art[From])
            if bf_result:
                return self.reject("Local Bad From (%s)"
                                   % bf_result.group(0), art, post)
        # Local Bad Groups
        if local and 'local_bad_groups' in self.bad_regexs:
            reg = self.bad_regexs['local_bad_groups']
            bg_result = reg.search(art[Newsgroups])
            if bg_result:
                return self.reject("Local Bad Group (%s)"
                                   % bg_result.group(0), art, post)

        # Local Bad Body
        if local and 'local_bad_body' in self.bad_regexs:
            reg = self.bad_regexs['local_bad_body']
            bb_result = reg.search(art[__BODY__])
            if bb_result:
                return self.reject("Local Bad Body (%s)"
                                   % bb_result.group(0), art, post)

        # Misplaced binary check
        if self.groups['bin_allowed_bool']:
            # All groups in the post match bin_allowed groups
            isbin = False
        else:
            # Potentially expensive check if article contains binary
            isbin = self.binary.isbin(art)
        # Generic 'binary' means it looks binary-like but doesn't match any
        # known encoding method.
        if isbin == 'binary':
            if config.getboolean('binary', 'reject_suspected'):
                return self.reject("Binary (%s)" % isbin, art, post)
            else:
                self.logart("Binary Suspect", art, post, "bin_suspect",
                            trim=False)
        elif isbin:
            self.binary.increment(post['feed-host'])
            return self.reject("Binary (%s)" % isbin, art, post)

        # Misplaced HTML check
        if (not self.groups['html_allowed_bool'] and
                config.getboolean('filters', 'reject_html') and
                'content_type' in post):
            if 'text/html' in post['content_type']:
                return self.reject("HTML Misplaced", art, post)
            if 'multipart' in post['content_type']:
                if config.getboolean('filters', 'reject_multipart'):
                    return self.reject("MIME Multpart", art, post)
                else:
                    logging.info('Multipart: %s' % mid)

        # Start of EMP checks
        if (not self.groups['emp_exclude_bool'] and
                not self.groups['test_bool']):
            ngs = ','.join(self.groups['groups'])
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
                if 'moderated' in self.groups and self.groups['moderated']:
                    logging.debug("Bypassing PHN filter due to moderated "
                                  "group in distribution")
                else:
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
                    'ihn_hosts' in self.bad_regexs and
                    not self.groups['ihn_exclude_bool']):
                ihn_result = self.bad_regexs['ihn_hosts']. \
                    search(post['injection-host'])
                if (ihn_result and
                        self.emp_ihn.add(post['injection-host'] + ngs)):
                    return self.reject("EMP IHN Reject", art, post)
            # Beginning of EMP Body filter.  Do this last, it's most
            # expensive in terms of processing.
            if art[__BODY__] is not None:
                if self.emp_body.add(art[__BODY__]):
                    return self.reject("EMP Body Reject", art, post)

        if local:
            # All tests passed.  Log the locally posted message.
            self.logart('Local Post', art, post, 'local_post')
        # The article passed all checks. Return an empty string.
        return ""

    def reject(self, reason, art, post):
        for logrule in self.log_rules.keys():
            if reason.startswith(logrule):
                self.logart(reason, art, post, self.log_rules[logrule])
                break
        logging.info("reject: mid=%s, reason=%s" % (art[Message_ID], reason))
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
            maxlines = config.get('logging', 'logart_maxlines')
            for line in str(art[__BODY__]).split('\n', maxlines)[:-1]:
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
        if startup:
            logging.info("Performing startup tasks")
        else:
            logging.info('Performing hourly tasks')
        self.emp_body.statlog()
        self.emp_fsl.statlog()
        self.emp_phl.statlog()
        self.emp_phn.statlog()
        self.emp_ihn.statlog()
        # Reload logging directives
        logging.debug('Reloading logging directives')
        self.log_rules = self.file2dict('log_rules')
        # Reload Injection-Host substrings
        logging.debug('Reloading Injection-Host substrings')
        self.ihsubs = self.file2list('ih_substrings')
        # Set up Regular Expressions
        for fn in self.bad_files.keys():
            new_regex = self.regex_file(fn)
            if new_regex:
                self.bad_regexs[fn] = new_regex
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
        self.hourly_trigger = future(hours=1)

    def midnight_events(self):
        """Events that need to occur at midnight each day.

        """
        logging.info('Performing midnight tasks')
        self.binary.report()
        self.emp_body.reset()
        self.emp_fsl.reset()
        self.emp_phl.reset()
        self.emp_phn.reset()
        self.emp_ihn.reset()
        # Set the midnight trigger for next day.
        self.midnight_trigger = next_midnight()

    def regex_file(self, filename):
        """Read a given file and return a regular expression composed of
        individual regex's on each line that have not yet expired.

        """
        logging.debug('Testing %s regex condition', filename)
        fqfn = os.path.join(config.get('paths', 'etc'), filename)
        if not os.path.isfile(fqfn):
            logging.debug('%s: Bad file not found' % filename)
            if filename in self.bad_regexs:
                # The file has been deleted so delete the regex.
                self.bad_regexs.pop(filename, None)
                # Reset the last_modified date to zero
                self.bad_file[filename] = 0
            return False
        current_mod_stamp = os.path.getmtime(fqfn)
        recorded_mod_stamp = self.bad_files[filename]
        if current_mod_stamp <= recorded_mod_stamp:
            logging.info('%s: File not modified so not recompiling',
                         filename)
            return False
        # The file has been modified: Recompile the regex
        logging.info('%s: Recompiling Regular Expression.', filename)
        # Reset the file's modstamp
        self.bad_files[filename] = current_mod_stamp
        # Make a local datetime object for now, just to save setting now in
        # the coming loop.
        bad_items = []
        n = now()
        f = open(fqfn, 'r')
        for line in f:
            valid = self.regex_bads.match(line)
            if valid:
                try:
                    # Is current time beyond that of the datestamp? If it is,
                    # the entry is considered expired and processing moves to
                    # the next entry.
                    if n > dateobj(valid.group(2)):
                        continue
                except ValueError:
                    # If the timestamp is invalid, just ignore the entry
                    continue
                # If processing gets here, the entry is a valid regex.
                bad_items.append(valid.group(1))
            elif line.lstrip().startswith('#'):
                # Don't do anything, it's a comment line
                pass
            elif len(line.strip()) == 0:
                # Blank lines are fine
                pass
            else:
                logging.warn("Invalid line in %s: %s", filename, line)
        f.close()
        num_bad_items = len(bad_items)
        if num_bad_items == 0:
            # No valid entires exist in the file.
            logging.debug('%s: No valid entries found' % filename)
            return False
        regex = '|'.join(bad_items)
        # This should never happen but best to check as || will match
        # everything.
        regex = regex.replace('||', '|')
        logging.info("Compiled %s rules from %s", num_bad_items, filename)
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
        self.emp_body.dump()
        self.emp_fsl.dump()
        self.emp_phl.dump()
        self.emp_phn.dump()
        self.emp_ihn.dump()


class Groups:
    def __init__(self):
        self.regex = Regex()
        # List of tests (that will become zeroed dict items).
        self.grps = ['test', 'bin_allowed', 'emp_exclude', 'ihn_exclude',
                     'html_allowed', 'sex_groups', 'moderated']

    def __getitem__(self, grptest):
        return self.grp[grptest]

    def __contains__(self, item):
        if item in self.grp:
            return True
        return False

    def analyze(self, newsgroups):
        # Zero all dict items we'll use in this post
        grp = dict((f, 0) for f in self.grps)
        
        nglist = str(newsgroups).lower().split(',')
        count = len(nglist)
        for ng in nglist:
            # Strip whitespace from individual Newsgroups
            ng = ng.strip()
            if self.regex.test.search(ng):
                grp['test'] += 1
            if self.regex.bin_allowed.search(ng):
                grp['bin_allowed'] += 1
            if self.regex.emp_exclude.search(ng):
                grp['emp_exclude'] += 1
            if self.regex.ihn_exclude.search(ng):
                grp['ihn_exclude'] += 1
            if self.regex.html_allowed.search(ng):
                grp['html_allowed'] += 1
            if self.regex.sex_groups.search(ng):
                grp['sex_groups'] += 1
            if INN.newsgroup(ng) == 'm':
                grp['moderated'] += 1
        # Not all bools will be meaningful but it's easier to create them
        # generically then specifically.
        for ngelement in grp.keys():
            ngbool = '%s_bool' % ngelement
            grp[ngbool] = grp[ngelement] == count
        grp['groups'] = sorted(nglist)
        grp['count'] = count
        self.grp = grp


class Regex:
    def __init__(self):
        # Test groups
        test = ['\.test(ing)?(?:$|\.)',
                '^es\.pruebas',
                '^borland\.public\.test2',
                '^cern\.testnews']
        self.test = self.regex_compile(test)
        # Binary groups
        bin_allowed = ['^bin[a.]', '\.bin[aei.]', '\.bin$', '^fur\.artwork',
                       '^alt\.anonymous\.messages$', '^de\.alt\.dateien',
                       '^rec\.games\.bolo$', '^comp\.security\.pgp\.test$',
                       '^sfnet\.tiedostot', '^fido\.', '^unidata\.',
                       '^alt\.security\.keydist', '^mailing\.',
                       '^linux\.', '^lucky\.freebsd', '^gnus\.',
                       '\.lists\.freebsd\.']
        self.bin_allowed = self.regex_compile(bin_allowed)
        html_allowed = ['^pgsql\.', '^relcom\.', '^gmane', 'microsoft',
                        '^mailing\.']
        self.html_allowed = self.regex_compile(html_allowed)
        # Exclude from all EMP filters
        emp_exclude = ['^alt\.anonymous\.messages', '^free\.', '^local\.',
                       '^relcom\.', '^mailing\.', '^fa\.', '\.cvs\.',
                       '^gnu\.']
        self.emp_exclude = self.regex_compile(emp_exclude)
        # Exclude groups from IHN filter
        ihn_exclude = ['^alt\.anonymous', '^alt\.privacy']
        self.ihn_exclude = self.regex_compile(ihn_exclude)
        # Bad posting-hosts
        bad_ph = ['newsguy\.com', 'tornevall\.net']
        self.bad_ph = self.regex_compile(bad_ph)
        # Sex groups
        sex_groups = ['^alt\.sex']
        self.sex_groups = self.regex_compile(sex_groups)

    def regex_compile(self, regexlist):
        textual = '|'.join(regexlist).replace('||', '|')
        return re.compile(textual)


class EMP:
    def __init__(self,
                 threshold=3,
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
        # Attempt to restore a previous EMP dump
        self.restore(name)
        self.fuzzy_15char = re.compile('\S{15,}')
        self.fuzzy_notletters = re.compile('[^a-zA-Z]')
        # Initialize some defaults
        self.stats = {'name': name,
                      'nexttrim': future(secs=timedtrim),
                      'processed': 0,
                      'accepted': 0,
                      'rejected': 0,
                      'threshold': threshold,
                      'ceiling': ceiling,
                      'maxentries': maxentries,
                      'timedtrim': timedtrim,
                      'dofuzzy': dofuzzy}
        logmes = '%(name)s initialized. '
        logmes += 'threshold=%(threshold)s, '
        logmes += 'ceiling=%(ceiling)s, '
        logmes += 'maxentries=%(maxentries)s, '
        logmes += 'timedtrim=%(timedtrim)s'
        logging.info(logmes % self.stats)

    def add(self, content):
        """The content, in this context, is any string we want to hash and
        check for EMP collisions.  In various places we refer to it as
        'hash fodder'.

        """
        self.stats['processed'] += 1
        if self.stats['dofuzzy']:
            # Strip long strings
            content = re.sub(self.fuzzy_15char, '', content)
            # Remove everything except a-zA-Z
            content = re.sub(self.fuzzy_notletters, '', content).lower()

        # Bail out if the byte length of the content isn't sufficient for
        # generating an effective, unique hash.
        if len(content) < 1:
            logging.debug("Null content in %s hashing fodder.",
                          self.stats['name'])
            return False

        # MD5 is weak in cryptographic terms, but do I care for the purpose
        # of EMP collision checking?  Obviously not or I'd use something else.
        h = md5(content).digest()
        if h in self.table:
            # When the ceiling is reached, stop incrementing the count.
            if self.table[h] < self.stats['ceiling']:
                self.table[h] += 1
            else:
                logging.debug("%s hash ceiling hit. Not incrementing counter.",
                              self.stats['name'])

        else:
            # See if it's time to perform a trim.  We only care about doing
            # this when a new entry is being made.
            if now() > self.stats['nexttrim']:
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
        # As the EMP table is about to be modified, oldsize records it prior
        # to doing any changes.  This is only used for reporting purposes.
        self.stats['oldsize'] = len(self.table)
        for h in self.table.keys():
            self.table[h] -= 1
            if self.table[h] <= 0:
                del self.table[h]
        self.stats['size'] = len(self.table)
        logging.info('%(name)s: Trimmed from %(oldsize)s to %(size)s',
                     self.stats)
        self.stats['nexttrim'] = \
            future(secs=self.stats['timedtrim'])

    def statlog(self):
        """Log details of the EMP hash."""
        self.stats['size'] = len(self.table)
        logging.info("%(name)s: size=%(size)s, processed=%(processed)s, "
                     "accepted=%(accepted)s, rejected=%(rejected)s",
                     self.stats)

    def dump(self):
        """Dump the EMP table to disk so we can reload it after a restart.

        """
        dumpfile = os.path.join(config.get('paths', 'lib'),
                                self.stats['name'] + ".db")
        dump = shelve.open(dumpfile, flag='n')
        for k in self.table:
            dump[k] = self.table[k]
        dump.close()

    def restore(self, name):
        """Restore an EMP dump from disk.

        """
        dumpfile = os.path.join(config.get('paths', 'lib'), name + ".db")
        if os.path.isfile(dumpfile):
            logging.info("Attempting restore of %s dump", name)
            dump = shelve.open(dumpfile, flag='r')
            # We seem unable to use copy functions between shelves and dicts
            # so we do it per record.  Speed is not essential at these times.
            for k in dump:
                self.table[k] = dump[k]
            dump.close()
            logging.info("Restored %s records to %s", len(self.table), name)
        else:
            logging.debug("%s: Dump file does not exist.  Doing a clean "
                          "initialzation.", dumpfile)

    def reset(self):
        """Reset counters for this emp filter.

        """
        self.stats['processed'] = 0
        self.stats['accepted'] = 0
        self.stats['rejected'] = 0


"""
Okay, that's the end of our class definition.  What follows is the
stuff you need to do to get it all working inside innd.
"""

if 'python_filter' not in dir():
    python_version = sys.version_info
    config = init_config()
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                 'warn': logging.WARN, 'error': logging.ERROR}
    logging.getLogger().setLevel(logging.DEBUG)
    logfile = logging.handlers.TimedRotatingFileHandler(
        os.path.join(config.get('paths', 'log'), 'pyclean.log'),
        when='midnight',
        interval=1,
        backupCount=config.getint('logging', 'retain'))
    logfile.setLevel(loglevels[config.get('logging', 'level')])
    logfile.setFormatter(logging.Formatter(logfmt, datefmt=datefmt))
    logging.getLogger().addHandler(logfile)

python_filter = InndFilter()
try:
    INN.set_filter_hook(python_filter)
    INN.syslog('n', "pyclean successfully hooked into INN")
except Exception, errmsg:    # Syntax for Python 2.x.
    INN.syslog('e', "Cannot obtain INN hook for pyclean: %s" % errmsg[0])

# This looks weird, but creating and interning these strings should let us get
# faster access to header keys (which innd also interns) by losing some strcmps
# under the covers.
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
