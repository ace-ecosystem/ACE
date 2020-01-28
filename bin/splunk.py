#!/usr/bin/python3
# vim: sw=4:ts=4:et

import datetime
import argparse
import logging
import os.path
import stat
import sys
import csv
import json
import re
from configparser import SafeConfigParser
from getpass import getpass

sys.path.append('lib')
sys.path.append('.')

import saq.splunk as splunklib

# Remove any proxy environment variables.
os.environ['http_proxy'] = ''
os.environ['https_proxy'] = ''

# encryption support
def encrypt_password(password):
    from Crypto.Cipher import ARC4
    from base64 import b64encode 
    memorized_password = getpass("Enter encryption password: ")
    memorized_password_check = getpass("Re-enter encryption password: ")
    if memorized_password != memorized_password_check:
        logging.fatal("passwords do not match")
        sys.exit(1)

    cipher = ARC4.new(memorized_password)
    return b64encode(cipher.encrypt(password))

def decrypt_password(encrypted_password):
    from Crypto.Cipher import ARC4
    from base64 import b64decode
    memorized_password = getpass("Enter encryption password: ")
    cipher = ARC4.new(memorized_password)
    return cipher.decrypt(b64decode(encrypted_password))

parser = argparse.ArgumentParser()
parser.add_argument('search', nargs=argparse.REMAINDER)
parser.add_argument('-c', '--config', required=False, default=None, dest='config_path',
    help="Path to optional configuration file.  Defaults to ~/.splunklib.ini")
parser.add_argument('--ignore-config', required=False, default=False, action='store_true', dest='ignore_config',
    help="Ignore any configuration files.")
parser.add_argument('-v' , '--verbose', required=False, action='store_true', default=False, dest='verbose',
    help="Log verbose messages.  Helps when debugging searches.")
parser.add_argument('-q' , '--quiet', required=False, action='store_true', default=False, dest='quiet',
    help="Only log error messages.")

parser.add_argument('-U', '--uri', required=False, default=None, dest='uri',
    help="The splunk URI to connect to.")
parser.add_argument('-u', '--user', required=False, default=None, dest='username',
    help="Your splunk username.")
parser.add_argument('-p', '--password', required=False, default=False, action='store_true', dest='password',
    help="Prompt for a password (will not echo.)")
parser.add_argument('-m', '--max-result-count', required=False, default=1000, type=int, dest='max_result_count',
    help="Maximum number of results to return.  Defaults to 1000")

parser.add_argument('-s', '--start-time', required=False, default=None, dest='start_time',
    help="Starting time in YYYY-MM-DD HH:MM:SS format.  Defaults to 24 hours before now.")
parser.add_argument('-e', '--end-time', required=False, default=None, dest='end_time',
    help="Ending time in YYYY-MM-DD HH:MM:SS format.  Defaults to now.")

parser.add_argument('-S', '--relative-start-time', required=False, default=None, dest='relative_start_time',
    help="Specify the starting time as a time relative to now in DD:HH:MM:SS format.")
parser.add_argument('-E', '--relative-end-time', required=False, default=None, dest='relative_end_time',
    help="Specify the ending time as a time relative to now in DD:HH:MM:SS format.")
parser.add_argument('--enviro', action='store', required=True, default='production', dest='enviro',
    help="Specify which splunk environment to query (default=production). These are the sections defined in your config file.")

# the options only apply in the default csv mode
parser.add_argument('--headers', required=False, default=False, action='store_true', dest='headers',
    help="Display headers in CSV output mode.")

# json display option
parser.add_argument('--json', required=False, default=False, action='store_true', dest='json',
    help="Output in JSON instead of CSV")

# redirect to a file
parser.add_argument('-o', '--output', required=False, default=None, dest='output',
    help="Send output to a file.  Default is stdout.")

# save the given configuration to file for use later
parser.add_argument('--save-config', required=False, default=False, action='store_true', dest='save_config',
    help="Save the given configuration options to ~/.splunklib")
parser.add_argument('--encrypt', required=False, default=False, action='store_true', dest='encrypt_password',
    help="Encrypt your splunk password with another password.")

parser.add_argument('--search-file', required=False, default=False, action='store', dest='search_file',
    help="File containing the search query.")

# adding this for use with url_click cloudphish hunt
parser.add_argument('-i', '--use-index-time', required=False, default=None, action='store_true', dest='use_index_time',
        help="Use __index time specs instead.")

parser.add_argument('--query-timeout', required=False, default=None, dest='query_timeout',
                    help="Amount of time (in HH:MM:SS format) until a query times out.  Defaults to 30 minutes.")

args = parser.parse_args()

logging_level = logging.WARNING
if args.quiet:
    logging_level = logging.ERROR
if args.verbose:
    logging_level = logging.DEBUG
logging.basicConfig(
    format='[%(asctime)s] [%(filename)s:%(lineno)d] [%(threadName)s] [%(levelname)s] - %(message)s', 
    level=logging_level)

# are we saving the configuration?
if args.save_config:
    config_path = os.path.join(os.path.expanduser('~'), '.splunklib.ini')
    with open(config_path, 'w') as fp:
        fp.write('[production]\n')
        if args.uri is not None:
            fp.write('uri = {0}\n'.format(args.uri))
        if args.username is not None:
            fp.write('username = {0}\n'.format(args.username))
        if args.password:
            password = getpass("Enter password: ")

            # test the authentication
            if args.uri is not None and args.username is not None:
                searcher = splunklib.SplunkQueryObject(
                    uri=args.uri,
                    username=args.username,
                    password=password)

                if not searcher.authenticate():
                    logging.error("invalid splunk credentials")
                    sys.exit(1)

            if args.encrypt_password:
                encrypted_password = encrypt_password(password)
                logging.debug("encrypted_password = {0}".format(encrypted_password))
                fp.write('encrypted_password = {0}\n'.format(encrypted_password))
            else:
                fp.write('password = {0}\n'.format(password))
                logging.warning("saving PLAIN TEXT PASSWORD (use --encrypt option)")


        if args.max_result_count is not None:
            fp.write('max_result_count = {0}\n'.format(str(args.max_result_count)))

    os.chmod(config_path, 0o600) # sane permissions
    logging.debug("updated configuration")
    sys.exit(0)

# do we have a configuration file?
config_path = os.path.join(os.path.expanduser('~'), '.splunklib.ini')
if args.config_path is not None:
    config_path = args.config_path

uri = None
username = None
encrypted_password = None
password = None
max_result_count = 1000

if os.path.exists(config_path) and not args.ignore_config:
    # load the settings from the configuration file
    config = SafeConfigParser()
    config.read(config_path)
    try:
        uri = config.get(args.enviro, 'uri')
        username = config.get(args.enviro, 'username')
        if config.has_option(args.enviro, 'encrypted_password'):
            encrypted_password = config.get(args.enviro, 'encrypted_password')
        else:
            if config.has_option(args.enviro, 'password'):
                # make sure permissions are sane
                if os.stat(config_path).st_mode & stat.S_IROTH:
                    sys.stderr.write("""
*** HEY CLOWN ***
your file permissions on {0} allow anyone to read your plain text splunk password!
use the --save-config option with --encrypt to save your configuration with an encrypted password or chmod o-rwx this file
so that other people cannot read it
*** END CLOWN MESSAGE ***
""".format(config_path))

                password = config.get(args.enviro, 'password')

        if config.has_option(args.enviro, 'max_result_count'):
            max_result_count = config.getint(args.enviro, 'max_result_count')

    except Exception as e:
        logging.warning("invalid configuration file {0}: {1}".format(config_path, str(e)))

# command line options override configuration values
if args.uri is not None:
    uri = args.uri
if args.username is not None:
    username = args.username
if args.password:
    password = getpass("Enter password: ")

if encrypted_password is not None:
    password = decrypt_password(encrypted_password)

if args.max_result_count is not None:
    max_result_count = args.max_result_count

# make sure we have what we need
fatal = False
if uri is None:
    logging.fatal("missing uri")
    fatal = True
if username is None:
    logging.fatal("missing username")
    fatal = True
if password is None:
    logging.fatal("missing password")
    fatal = True
search_text = None
if args.search_file:
    if os.path.isfile(args.search_file):
        with open(args.search_file, 'r') as fp:
            search_text = fp.read()
            # comments in the search files are lines that start with #
            search_text = re.sub(r'^\s*#.*$', '', search_text, count=0, flags=re.MULTILINE)
            # put it all on one line for splunk
            # we don't *need* to do this except for keeping the logs clean
            search_text = re.sub(r'\n', ' ', search_text, count=0)
        # removeing time_spec allows us to pass hunt files from the cli
        if '{time_spec}' in search_text:
            search_text = search_text.format(time_spec="")
        args.search = search_text
    else:
        logging.fatal("search file does not exist") 
if len(args.search) < 1:
    logging.fatal("missing search")
    fatal = True

if fatal:
    sys.exit(1)

query = None
if args.search_file:
    query = search_text
else:
    query = ' '.join(args.search)

# figure out the time range given the options
start_time = None
end_time = None
datetime_format = '%Y-%m-%d %H:%M:%S'

if args.start_time is not None:
    start_time = datetime.datetime.strptime(args.start_time, datetime_format)

if args.end_time is not None:
    end_time = datetime.datetime.strptime(args.end_time, datetime_format)

if args.relative_start_time is not None:
    start_time = datetime.datetime.now() - splunklib.create_timedelta(args.relative_start_time)
if args.relative_end_time is not None:
    end_time = datetime.datetime.now() - splunklib.create_timedelta(args.relative_end_time)

if start_time is not None and end_time is None:
    end_time = datetime.datetime.now()

if start_time is None and 'earliest' not in query.lower():
    logging.debug("defaulting to past 24 hours")
    start_time = datetime.datetime.now() - splunklib.create_timedelta('00:24:00:00')
    end_time = datetime.datetime.now()

#if args.use_index_time:
#    time_spec = '_index_earliest = {0} _index_latest = {1}'.format(start_time, end_time)

searcher = splunklib.SplunkQueryObject(
    uri=uri,
    username=username,
    password=password,
    max_result_count=max_result_count,
    query_timeout=args.query_timeout if args.query_timeout else '00:30:00')

search_result = False
try:
    if start_time is not None and end_time is not None:
        if args.use_index_time:
            search_result = searcher.query_with_index_time(query, start_time, end_time)
        else:
            search_result = searcher.query_with_time(query, start_time, end_time)
    else:
        search_result = searcher.query(query)
except KeyboardInterrupt:
    pass

if not search_result:
    logging.error("searched failed")
    sys.exit(1)

output_fp = sys.stdout
if args.output:
    output_fp = open(args.output, 'w', encoding='utf-8')

# JSON output
if args.json:
    output_fp.write(json.dumps({
        'search': query,
        'username': username,
        'uri': uri,
        'max_result_count': max_result_count,
        'result': searcher.json() }))
    sys.exit(0)

# or CSV output
writer = csv.writer(output_fp)
# write the header?
if args.headers:
    writer.writerow(searcher['fields'])

for row in searcher['rows']:

    # see http://stackoverflow.com/a/9942885
    #row = [x.encode('utf-8') if isinstance(x, str) else x for x in row]

    writer.writerow(row)

sys.exit(0)
