#!/usr/bin/env python

# check_all_disks.py
#
# This script is based on Nagios check_ncpa.py
# It pulls a list of all disks on a server from the NCPA agent
# and runs a space check for all drives / filesystems.
#
# Initial version 1.0.0                Steve Zwart 04/02/2022
# Add numeric check in case of errors  Steve Zwart 04/20/2022
# returned in used_percent field.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
 

"""
SYNOPSIS


"""
import sys
import optparse
import traceback
import ssl

# Python 2/3 Compatibility imports

try:
    import json
except ImportError:
    import simplejson as json

try:
    import urllib.request
    import urllib.parse
    import urllib.error
except ImportError:
    import urllib2
    import urllib

try:
    urlencode = urllib.parse.urlencode
except AttributeError:
    urlencode = urllib.urlencode

try:
    urlopen = urllib.request.urlopen
except AttributeError:
    urlopen = urllib2.urlopen

try:
    urlquote = urllib.parse.quote
except AttributeError:
    urlquote = urllib.quote

try:
    urlerror = urllib.error.URLError
except AttributeError:
    urlerror = urllib2.URLError

try:
    httperror = urllib.error.HTTPError
except AttributeError:
    httperror = urllib2.HTTPError

import shlex
import re
import signal


__VERSION__ = '1.0.0'


class ConnectionError(Exception):
    error_output_prefix = "UNKNOWN: An error occured connecting to API. "
    pass

class URLError(ConnectionError):
    def __init__(self, error_message):
        self.error_message = ConnectionError.error_output_prefix + "(Connection error: '" + error_message + "')"

class HTTPError(ConnectionError):
    def __init__(self, error_message):
        self.error_message = ConnectionError.error_output_prefix + "(HTTP error: '" + error_message + "')"


def parse_args():
    version = 'check_all_disks.py, Version %s' % __VERSION__

    parser = optparse.OptionParser()
    parser.add_option("-H", "--hostname", help="The hostname to be connected to.")
    parser.add_option("-P", "--port", default=5693, type="int",
                      help="Port to use to connect to the client.")
    parser.add_option("-w", "--warning", default=None, type="str",
                      help="Warning value to be passed for the check.")
    parser.add_option("-c", "--critical", default=None, type="str",
                      help="Critical value to be passed for the check.")
    parser.add_option("-t", "--token", default='',
                      help="The token for connecting.")
    parser.add_option("-a", "--arguments", default=None,
                      help="Arguments for the plugin to be run. Not necessary "
                           "unless you're running a custom plugin. Given in the same "
                           "as you would call from the command line. Example: -a '-w 10 -c 20 -f /usr/local'")
    parser.add_option("-T", "--timeout", default=60, type="int",
                      help="Enforced timeout, will terminate plugins after "
                           "this amount of seconds. [%default]")
    parser.add_option("-v", "--verbose", action='store_true',
                      help='Print more verbose error messages.')
    parser.add_option("-x", "--exclude", type=str,
                      help="Comma separated list of drives to exclude from the check."
                           " Use separator | instead of \ or /. "
                           "Example -x 'T:|,E:|' to exclude Windows drives T:\ and E:\ "
                           "Example -x '|mkcd|cd_images' to exclude Unix /mkcd/cd_images")
    parser.add_option("-D", "--debug", action='store_true',
                      help='Print LOTS of error messages. Used mostly for debugging.')
    parser.add_option("-V", "--version", action='store_true',
                      help='Print version number of plugin.')
#   parser.add_option("-q", "--queryargs", default=None,
#                     help='Extra query arguments to pass in the NCPA URL.')
    parser.add_option("-s", "--secure", action='store_true', default=False,
                      help='Require successful certificate verification. Does not work on Python < 2.7.9.')
#   parser.add_option("-p", "--performance", action='store_true', default=False,
#                     help='Print performance data even when there is none. '
#                          'Will print data matching the return code of this script')
    options, _ = parser.parse_args()

    if options.version:
        print(version)
        sys.exit(0)

    if not options.hostname:
        parser.print_help()
        parser.error("Hostname is required for use.")

    if not options.critical:
        parser.print_help()
        parser.error("critical is required for use.")

    if not options.warning:
        parser.print_help()
        parser.error("warning is required for use.")

# We are specifically retrieving the disk/logical data from NCPA
#   options.metric = re.sub(r'^/?(api/)?', '', options.metric)
    options.metric = "disk/logical"

#   print options
    return options


# ~ The following are all helper functions. I would normally split these out into
# ~ a new module but this needs to be portable.


def get_url_from_options(options):
    host_part = get_host_part_from_options(options)
    arguments = get_arguments_from_options(options)
    return '%s?%s' % (host_part, arguments)


def get_host_part_from_options(options):
    """Gets the address that will be queries for the JSON.

    """
    hostname = options.hostname
    port = options.port

    if not options.metric is None:
        metric = urlquote(options.metric)
    else:
        metric = ''

    arguments = get_check_arguments_from_options(options)
    if not metric and not arguments:
        api_address = 'https://%s:%d/api' % (hostname, port)
    else:
        api_address = 'https://%s:%d/api/%s/%s' % (hostname, port, metric, arguments)

    return api_address


def get_check_arguments_from_options(options):
    """Gets the escaped URL for plugin arguments to be added
    to the end of the host URL. This is different from the get_arguments_from_options
    in that this is meant for the syntax when the user is calling a check, whereas the below
    is when GET arguments need to be added.

    """
    arguments = options.arguments
    if arguments is None:
        return ''
    else:
        lex = shlex.shlex(arguments)
        lex.whitespace_split = True
        arguments = '/'.join([urlquote(x, safe='') for x in lex])
        return arguments


def get_arguments_from_options(options, **kwargs):
    """Returns the http query arguments. If there is a list variable specified,
    it will return the arguments necessary to query for a list.

    """

    # Note: Changed back to units due to the units being what is passed via the
    # API call which can confuse people if they don't match
    arguments = { 'token': options.token }
    
# We remove insertion of arguments since we're just pulling data
#   if not options.list:
#       arguments['warning'] = options.warning
#       arguments['critical'] = options.critical
#       arguments['delta'] = options.delta
#       arguments['check'] = 1

    args = list((k, v) for k, v in list(arguments.items()) if v is not None)

    # Get the options (comma separated)
#   if options.queryargs:
#       # for each comma, perform lookahead, split if we aren't inside quotes.
#       arguments_list = re.split(''',(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', options.queryargs)
#       for argument in arguments_list:
#           key, value = argument.split('=', 1)
#           if value is not None:
#               args.append((key, value))

    #~ Encode the items in the dictionary that are not None
    return urlencode(args)


def get_json(options):
    """Get the page given by the options. This will call down the url and
    encode its finding into a Python object (from JSON).

    """

    url = get_url_from_options(options)

    if options.verbose:
        print('Connecting to: ' + url)

    try:

        try:
            ctx = ssl.create_default_context()
            if not options.secure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ret = urlopen(url, context=ctx)
        except AttributeError:
            ret = urlopen(url)

    except httperror as e:
        try:
            raise HTTPError('{0} {1}'.format(e.code, e.reason))
        except AttributeError:
            raise HTTPError('{0}'.format(e.code))
    except urlerror as e:
        raise URLError('{0}'.format(e.reason))

    ret = ret.read()

# Uncomment this to see the whole data stream returned back by NCPA
#   if options.verbose:
#       print('File returned contained:\n' + ret.decode('utf-8'))

    arr = json.loads(ret)

    return arr


def run_check(info_json):
    """Run a check against the remote host.

    """
    if 'printline' in info_json and 'returncode' in info_json:
        return info_json['printline'], info_json['returncode']
    elif 'error' in info_json:
        return info_json['error'], 3


def show_list(info_json):
    """Show the list of available options.

    """
    return json.dumps(info_json, indent=4), 0


def timeout_handler(threshold):
    def wrapped(signum, frames):
        printline = "UNKNOWN: Execution exceeded timeout threshold of %ds" % threshold
        print(printline)
        sys.exit(3)
    return wrapped


def main():
    options = parse_args()
    valid_fstypes = ["NTFS", "FAT", "FAT32", "jfs", "jfs2", "btrfs", "ext2", "ext3", "ext4", "xfs"]

    # We need to ensure that we will only execute for a certain amount of
    # seconds.
    signal.signal(signal.SIGALRM, timeout_handler(options.timeout))
    signal.alarm(options.timeout)

    try:
        if options.version:
            printline = 'The version of this plugin is %s' % __VERSION__
            return printline, 0

        info_json = get_json(options)

#       Some debug statements during development
#       print(info_json['logical']['C:|']['used_percent'][0])
#       print(info_json['logical']['C:|']['fstype'])
#       print("warning level",options.warning,"critical level",options.critical)

# Loop through the drives and look at percent used.

        if options.exclude:
          excludelist = options.exclude.split(",")
          if options.verbose:
            print "Exclude list:"
            for x in range(len(excludelist)):
              print excludelist[x]
        nbrerrors = 0
        returncode = 0
        printline = ""
        for drive in info_json['logical']:
# Filter out EMC Networker temp drives
          if "EMC NetWorker|nsr" in drive:
            continue
          if options.exclude:
            match_exclude = "n"
            for x in range(len(excludelist)):
              if drive == excludelist[x]:
                match_exclude = "y"
# Break out of outer loop if drive is excluded
          if match_exclude == "y":
            continue
          drive_used_percent = info_json['logical'][drive]['used_percent'][0]
          drive_fstype = info_json['logical'][drive]['fstype']
          if options.verbose:
            print drive,drive_used_percent,drive_fstype
          try:
            index = valid_fstypes.index(drive_fstype)
          except:
#           Bypass unknown fstype
            continue
          if options.verbose:
            print "fstype is supported"
# Use try in case of non-numeric Error XXX returned in drive_used_percent
          try:
            if float(drive_used_percent) > float(options.critical):
              nbrerrors = nbrerrors + 1
              if nbrerrors > 1:
                printline = printline + ", "
              printline = printline + drive + " is critical. Used percent: " + str(drive_used_percent)
              returncode = 2
            elif float(drive_used_percent) > float(options.warning):
              nbrerrors = nbrerrors + 1
              if nbrerrors > 1:
                printline = printline + ", "
              printline = printline + drive + " is warning. Used percent: " + str(drive_used_percent)
              if returncode < 1:
                returncode = 1
          except:
#           Bypass non-numeric
            continue
          
        if returncode == 0:
          printline = "OK: success"
        if returncode == 2:
          printline = "CRITICAL: " + printline
        if returncode == 1:
          printline = "WARNING: " + printline
# Replace any pipe symbol drive separators with forward slash
        printline = printline.replace('|', '/')
        return printline, returncode

    except (HTTPError, URLError) as e:
        if options.debug:
            return 'The stack trace:\n' + traceback.format_exc(), 3
        elif options.verbose:
            return 'An error occurred:\n' + str(e.error_message), 3
        else:
            return e.error_message, 3
    except Exception as e:
        if options.debug:
            return 'The stack trace:\n' + traceback.format_exc(), 3
        elif options.verbose:
            return 'An error occurred:\n' + str(e), 3
        else:
            return 'UNKNOWN: Error occurred while running the plugin. Use the verbose flag for more details.', 3

if __name__ == "__main__":
   printline, returncode = main()
   if sys.version_info[0] < 3:
      print(unicode(printline).encode('utf-8'))
   else:
      print(printline.encode().decode('utf-8'))
   sys.exit(returncode)
