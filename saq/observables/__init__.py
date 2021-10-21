import base64
import hashlib
import io
import ipaddress
import logging
import os.path
import pickle
import re
import unicodedata
import html

from subprocess import Popen, PIPE
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from urlfinderlib import find_urls
from urlfinderlib import is_url

import saq
from saq.analysis import Observable, DetectionPoint
from saq.constants import *
from saq.carbon_black import get_cbc_ioc_status, get_cbc_ioc_details
from saq.email import normalize_email_address, normalize_message_id
from saq.error import report_exception
from saq.gui import *
from saq.integration import integration_enabled
from saq.intel import query_sip_indicator
from saq.remediation import RemediationTarget
from saq.database import Remediation, get_db_connection

from saq.util import is_subdomain

import iptools

__all__ = [
    'ObservableValueError',
    'CaselessObservable',
    'IPv4Observable',
    'IPv4ConversationObservable',
    'IPv4FullConversationObservable',
    'FQDNObservable',
    'HostnameObservable',
    'AssetObservable',
    'UserObservable',
    'URLObservable',
    'FileObservable',
    'FilePathObservable',
    'FileNameObservable',
    'FileLocationObservable',
    'EmailAddressObservable',
    'YaraRuleObservable',
    'IndicatorObservable',
    'MD5Observable',
    'SHA1Observable',
    'SHA256Observable',
    'EmailConversationObservable',
    'SnortSignatureObservable',
    'TestObservable',
    'create_observable' ]

# 
# custom Observable types
#

class ObservableValueError(ValueError):
    pass

class DefaultObservable(Observable):
    """If an observable type does not match a known type then this class is used to represent it."""
    pass

class CaselessObservable(Observable):
    """An observable that doesn't care about the case of the value."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    # see https://stackoverflow.com/a/29247821
    def normalize_caseless(self, value):
        if value is None:
            return None

        return unicodedata.normalize("NFKD", value.casefold())

    def _compare_value(self, other):
        return self.normalize_caseless(self.value) == self.normalize_caseless(other)

class IPv4Observable(Observable):

    def __init__(self, *args, **kwargs):
        super().__init__(F_IPV4, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        # type check the value
        try:
            ipaddress.IPv4Address(new_value)
        except Exception as e:
            raise ObservableValueError(f"{new_value} is not a valid ipv4 address")

        self._value = new_value.strip()
    
    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
            result.extend(super().jinja_available_actions)

        return result

    def is_managed(self):
        """Returns True if this IP address is listed as part of a managed network, False otherwise."""
        # see [network_configuration]
        # these are initialized in the global initialization function
        for cidr in saq.MANAGED_NETWORKS:
            try:
                if self.value in cidr:
                    return True
            except:
                return False

        return False

    def matches(self, value):
        # is this CIDR notation?
        if '/' in value:
            try:
                return self.value in iptools.IpRange(value)
            except:
                pass

        # otherwise it has to match exactly
        return self.value == value

class IPv4ConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        self._source = None
        self._dest = None
        super().__init__(F_IPV4_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        parsed_ipv4_conversation = parse_ipv4_conversation(self.value)
        if len(parsed_ipv4_conversation) == 2:
            self._source, self._dest = parsed_ipv4_conversation
        else:
            raise ObservableValueError(f"invalid IPv4 Convo: {new_value}")
        
    @property
    def source(self):
        return self._source

    @property
    def destination(self):
        return self._dest

class IPv4FullConversationObservable(Observable):
    
    def __init__(self, *args, **kwargs):
        self._source = None
        self._source_port = None
        self._dest = None 
        self._dest_port = None
        super().__init__(F_IPV4_FULL_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        parsed_ipv4_full_conversation = parse_ipv4_full_conversation(self.value)
        if len(parsed_ipv4_full_conversation) == 4:
            self._source, self._source_port, self._dest, self._dest_port = parsed_ipv4_full_conversation
        else:
            raise ObservableValueError(f"invalid IPv4 Full Convo: {new_value}")

    @property
    def source(self):
        return self._source

    @property
    def source_port(self):
        return self._source_port

    @property
    def dest(self):
        return self._dest

    @property   
    def dest_port(self):
        return self._dest_port

class FQDNObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FQDN, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
            result.extend(super().jinja_available_actions)

        return result

    def is_managed(self):
        """Returns True if this FQDN is a managed DN."""
        for fqdn in saq.CONFIG['global']['local_domains'].split(','):
            if is_subdomain(self.value, fqdn):
                return True

        return False

class HostnameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_HOSTNAME, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class AssetObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_ASSET, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class UserObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_USER, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_available_actions(self):
        result = []
        result.append(ObservableActionViewInExabeam())
        result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result


PROTECTED_URLS = ['egnyte.com', 'fireeye.com', 'safelinks.protection.outlook.com', 'dropbox.com', 'drive.google.com', '.sharepoint.com',
                  'proofpoint.com']


class URLObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_URL, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        # Extract URL from known protected URLs, if necessary
        if any(url in self.value for url in PROTECTED_URLS):
            self.sanitize_protected_urls()

        # Use urlfinderlib to make sure this is a valid URL before creating the observable
        if not is_url(self.value):
            raise ObservableValueError("invalid URL {}".format(self.value))

    @property
    def sha256(self):
        """Returns the sha256 value of this URL suitable for cloudphish processing."""
        from saq.cloudphish import hash_url

        if hasattr(self, '_sha256'):
            return self._sha256

        self._sha256 = hash_url(self.value)
        return self._sha256

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUrlCrawl(), ObservableActionSeparator() , ObservableActionClearCloudphishAlert()]
        result.extend(super().jinja_available_actions)
        return result

    def sanitize_protected_urls(self):
        """Is this URL protected by another company by wrapping it inside another URL they check first?"""

        extracted_url = None

        try:
            parsed_url = urlparse(self.value)
        except Exception as e:
            logging.error("unable to parse url {}: {}".format(self.value, e))
            return

        # egnyte links
        if parsed_url.netloc.lower().endswith('egnyte.com'):
            if parsed_url.path.startswith('/dl/'):
                extracted_url = self.value.replace('/dl/', '/dd/')
                logging.info("translated egnyte.com url {} to {}".format(self.value, extracted_url))

        # fireeye links
        elif parsed_url.netloc.lower().endswith('fireeye.com'):
            if parsed_url.netloc.lower().startswith('protect'):
                qs = parse_qs(parsed_url.query)
                if 'u' in qs:
                    extracted_url = qs['u'][0]

        # "safelinks" by outlook
        elif parsed_url.netloc.lower().endswith('safelinks.protection.outlook.com'):
            qs = parse_qs(parsed_url.query)
            if 'url' in qs:
                extracted_url = qs['url'][0]

        # dropbox links
        elif parsed_url.netloc.lower().endswith('.dropbox.com'):
            qs = parse_qs(parsed_url.query)
            modified = False
            if 'dl' in qs:
                if qs['dl'] == ['0']:
                    qs['dl'] = '1'
                    modified = True
            else:
                qs['dl'] = '1'
                modified = True

            if modified:
                # rebuild the query
                extracted_url = urlunparse((parsed_url.scheme,
                                           parsed_url.netloc,
                                           parsed_url.path,
                                           parsed_url.params,
                                           urlencode(qs),
                                           parsed_url.fragment))

        # sharepoint download links
        elif parsed_url.netloc.lower().endswith('.sharepoint.com'):
            # user gets this link in an email
            # https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD
            # needs to turn into this link
            # https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ

            # so the URL format seems to be this
            # https://SITE.shareponit.com/:b:/g/PATH/ID?e=DATA
            # not sure if NAME can contain subdirectories so we'll assume it can
            regex_sharepoint = re.compile(r'^/:b:/g/(.+)/([^/]+)$')
            m = regex_sharepoint.match(parsed_url.path)
            parsed_qs = parse_qs(parsed_url.query)
            if m and 'e' in parsed_qs:
                extracted_url = urlunparse((parsed_url.scheme,
                                            parsed_url.netloc,
                                            '/{}/_layouts/15/download.aspx'.format(m.group(1)),
                                            parsed_url.params,
                                            urlencode({'e': parsed_qs['e'][0], 'share': m.group(2)}),
                                            parsed_url.fragment))

                logging.info("translated sharepoint url {} to {}".format(self.value, extracted_url))

        # google drive links
        regex_google_drive = re.compile(r'drive\.google\.com/file/d/([^/]+)/view')
        m = regex_google_drive.search(self.value)
        if m:
            # sample
            # https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view
            # turns into
            # https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download

            google_id = m.group(1)

            extracted_url = 'https://drive.google.com/uc?authuser=0&id={}&export=download'.format(google_id)
            logging.info("translated google drive url {} to {}".format(self.value, extracted_url))

        if parsed_url.netloc.lower().endswith('.proofpoint.com'):
            extracted_url_set = find_urls(self.value)
            if extracted_url_set:
                # loop through all extrected URLs to remove any nested protected URLs
                for possible_url in extracted_url_set.copy():
                    if any(url in possible_url for url in PROTECTED_URLS):
                        extracted_url_set.remove(possible_url)

                # make sure that the set still has URLs in it
                if extracted_url_set:
                    extracted_url = extracted_url_set.pop()

        # Add additional simple protected URL sanitizaitons here
        # If sanitization requires redirect/additional analysis, add to saq.modules.url.ProtectedURLAnalyzer

        # return junk if this a malformed protected URL/proofpoint entaglement so we don't add it as an observable
        if not extracted_url and 'proofpoint.com' in self.value:
            extracted_url = 'NOT_A_URL'

        if extracted_url:
            self.value = extracted_url


class FileObservable(Observable):

    KEY_MD5_HASH = 'md5_hash'
    KEY_SHA1_HASH = 'sha1_hash'
    KEY_SHA256_HASH = 'sha256_hash'
    KEY_MIME_TYPE = 'mime_type'

    def __init__(self, *args, **kwargs):
        self._md5_hash = None
        self._sha1_hash = None
        self._sha256_hash = None

        self._mime_type = None

        self._scaled_width = None
        self._scaled_height = None

        super().__init__(F_FILE, *args, **kwargs)

        # some directives are inherited by children
        self.add_event_listener(EVENT_RELATIONSHIP_ADDED, self.handle_relationship_added)

    @Observable.value.setter
    def value(self, new_value):
        # do not allow empty file names
        if not new_value:
            raise ObservableValueError("empty file name")

        self._value = new_value

    #
    # in ACE the value of the F_FILE observable is the relative path to the content (inside the storage directory)
    # so when we want to look up the tag mapping we really want to look up the content
    # so we use the F_SHA256 value for this purpose instead
        
    @property
    def tag_mapping_type(self):
        return F_SHA256

    @property
    def tag_mapping_value(self):
        return self.sha256_hash

    @property
    def tag_mapping_md5_hex(self):
        if self.sha256_hash is None:
            return None

        md5_hasher = hashlib.md5()
        md5_hasher.update(self.sha256_hash.encode('utf8', errors='ignore'))
        return md5_hasher.hexdigest()

    @property
    def json(self):
        result = Observable.json.fget(self)
        result.update({
            FileObservable.KEY_MD5_HASH: self.md5_hash,
            FileObservable.KEY_SHA1_HASH: self.sha1_hash,
            FileObservable.KEY_SHA256_HASH: self.sha256_hash,
            FileObservable.KEY_MIME_TYPE: self._mime_type,
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        Observable.json.fset(self, value)

        if FileObservable.KEY_MD5_HASH in value:
            self._md5_hash = value[FileObservable.KEY_MD5_HASH]
        if FileObservable.KEY_SHA1_HASH in value:
            self._sha1_hash = value[FileObservable.KEY_SHA1_HASH]
        if FileObservable.KEY_SHA256_HASH in value:
            self._sha256_hash = value[FileObservable.KEY_SHA256_HASH]
        if FileObservable.KEY_MIME_TYPE in value:
            self._mime_type = value[FileObservable.KEY_MIME_TYPE]

    @property
    def md5_hash(self):
        self.compute_hashes()
        return self._md5_hash

    @property
    def sha1_hash(self):
        self.compute_hashes()
        return self._sha1_hash

    @property
    def sha256_hash(self):
        self.compute_hashes()
        return self._sha256_hash

    def compute_hashes(self):
        """Computes the md5, sha1 and sha256 hashes of the file and stores them as properties."""

        if self._md5_hash is not None and self._sha1_hash is not None and self._sha256_hash is not None:
            return True

        # sanity check
        # you need the root storage_dir to get the correct path
        if self.root is None:
            logging.error("compute_hashes was called before root was set for {}".format(self))
            return False

        if self.root.storage_dir is None:
            logging.error("compute_hashes was called before root.storage_dir was set for {}".format(self))
            return False
        
        md5_hasher = hashlib.md5()
        sha1_hasher = hashlib.sha1()
        sha256_hasher = hashlib.sha256()
    
        try:
            with open(self.path, 'rb') as fp:
                while True:
                    data = fp.read(io.DEFAULT_BUFFER_SIZE)
                    if data == b'':
                        break

                    md5_hasher.update(data)
                    sha1_hasher.update(data)
                    sha256_hasher.update(data)

        except Exception as e:
            # this will happen if a F_FILE observable refers to a file that no longer (or never did) exists
            logging.debug(f"unable to compute hashes of {self.value}: {e}")
            return False
        
        md5_hash = md5_hasher.hexdigest()
        sha1_hash = sha1_hasher.hexdigest()
        sha256_hash = sha256_hasher.hexdigest()
        logging.debug("file {} has md5 {} sha1 {} sha256 {}".format(self.path, md5_hash, sha1_hash, sha256_hash))

        self._md5_hash = md5_hash
        self._sha1_hash = sha1_hash
        self._sha256_hash = sha256_hash

        return True

    @property
    def display_preview(self):
        try:
            with open(self.path, 'rb') as fp:
                return fp.read(saq.CONFIG['gui'].getint('file_preview_bytes')).decode('utf8', errors='replace')
        except FileNotFoundError:
            logging.error(f"file does not exist for display_preview: {self.path}")
            return None

    @property
    def jinja_template_path(self):
        return "analysis/file_observable.html"

    @property
    def mime_type(self):
        if self._mime_type:
            return self._mime_type

        p = Popen(['file', '-b', '--mime-type', '-L', self.path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

        if len(stderr) > 0:
            logging.warning("file command returned error output for {}".format(self.path))

        self._mime_type = stdout.decode(errors='ignore').strip()
        #logging.info("MARKER: {} mime type {}".format(self.path, self._mime_type))
        return self._mime_type

    @property
    def path(self):
        return os.path.join(saq.SAQ_RELATIVE_DIR, self.root.storage_dir, self.value)

    @property
    def ext(self):
        """Returns the file extension of this file in lower case, or None if it doesn't have one."""
        if '.' not in self.value:
            return None

        try:
            return os.path.basename(self.value).split('.')[-1].lower()
        except Exception as e:
            logging.error("unable to get file extension of {}: {}".format(self, e))
            return None

    @property
    def exists(self):
        try:
            #logging.info("checking stat of {}".format(self.path))
            return os.path.exists(self.path)
        except Exception as e:
            logging.warning("unable to stat path: {}".format(e))
            #report_exception()
            return False

    @property
    def size(self):
        try:
            return os.path.getsize(self.path)
        except Exception as e:
            logging.warning("unable to get size: {}".format(e))
            return 0

    @property
    def human_readable_size(self):
        from math import log2

        _suffixes = ['bytes', 'K', 'M', 'G', 'T', 'E', 'Z']

        # determine binary order in steps of size 10 
        # (coerce to int, // still returns a float)
        order = int(log2(self.size) / 10) if self.size else 0
        # format file size
        # (.4g results in rounded numbers for exact matches and max 3 decimals, 
        # should never resort to exponent values)
        return '{:.4g} {}'.format(self.size / (1 << (order * 10)), _suffixes[order])

    @property
    def jinja_available_actions(self):
        result = []
        if self.exists:
            result.append(ObservableActionDownloadFile())
            result.append(ObservableActionDownloadFileAsZip())
            result.append(ObservableActionSeparator())
            result.append(ObservableActionViewAsHex())
            result.append(ObservableActionViewAsText())
            if integration_enabled('vt') or integration_enabled('vx') or integration_enabled('falcon_sandbox'):
                result.append(ObservableActionSeparator())
                if integration_enabled('vt'):
                    result.append(ObservableActionUploadToVt())
                if integration_enabled('vx'):
                    result.append(ObservableActionUploadToVx())
                if integration_enabled('falcon_sandbox'):
                    result.append(ObservableActionUploadToFalconSandbox())
            
            if any([x for x in saq.CONFIG.keys() if x.startswith('send_file_to_')]):
                result.append(ObservableActionSeparator())
                result.append(ObservableActionFileSendTo())
            
            result.append(ObservableActionSeparator())
            result.append(ObservableActionViewInVt())
            if integration_enabled('vx'):
                result.append(ObservableActionViewInVx())
            if integration_enabled('falcon_sandbox'):
                result.append(ObservableActionViewInFalconSandbox())
            result.append(ObservableActionFileRender())

            result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result

    @property
    def is_image(self):
        """Returns True if the file command thinks this file is an image."""
        if self.mime_type is None:
            return False

        return self.mime_type.startswith('image')

    def compute_scaled_dimensions(self):
        from PIL import Image
        try:
            with Image.open(self.path) as image:
                width, height = image.size
        except Exception as e:
            logging.warning("unable to parse image {}: {}".format(self.path, e))
            return

        w_ratio = 1.0
        h_ratio = 1.0

        if width > 640:
            w_ratio = 640.0 / float(width)

        if height > 480:
            h_ratio = 480.0 / float(height)

        ratio = w_ratio if w_ratio > h_ratio else h_ratio
        self._scaled_width = int(width * ratio)
        self._scaled_height = int(height * ratio)
        #logging.info("MARKER: using ratio {} scaled width {} scaled height {}".format(ratio, self._scaled_width, self._scaled_height))

    @property
    def scaled_width(self):
        if not self.is_image:
            return None

        if self._scaled_width:
            return self._scaled_width

        self.compute_scaled_dimensions()
        return self._scaled_width

    @property
    def scaled_height(self):
        if not self.is_image:
            return None

        if self._scaled_height:
            return self._scaled_height

        self.compute_scaled_dimensions()
        return self._scaled_height

    def handle_relationship_added(self, source, event, target, relationship=None):
        pass
        #if relationship.target.has_directive(DIRECTIVE_EXTRACT_URLS):
            #logging.debug("{} inherited directive {} from {}".format(
                          #self, DIRECTIVE_EXTRACT_URLS, relationship.target))
            #self.add_directive(DIRECTIVE_EXTRACT_URLS)

class FilePathObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_PATH, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class FileNameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_NAME, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class FileLocationObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_LOCATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value
        self._hostname, self._full_path = parse_file_location(self.value)

    @property
    def hostname(self):
        return self._hostname

    @property
    def full_path(self):
        return self._full_path

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionCollectFile(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

    @property
    def jinja_template_path(self):
        return "analysis/file_location_observable.html"

class EmailAddressObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_ADDRESS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        # normalize email addresses
        normalized = normalize_email_address(new_value)
        if not normalized:
            logging.warning(f"unable to normalize email address {new_value}")
        else:
            self._value = normalized

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class EmailDeliveryObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_DELIVERY, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        self.message_id, self.email_address = parse_email_delivery(self.value)
        self.message_id = normalize_message_id(self.message_id)
        self._value = create_email_delivery(self.message_id, self.email_address)

    @property
    def jinja_template_path(self):
        return "analysis/email_delivery_observable.html"

    @property
    def remediation_targets(self):
        return [RemediationTarget('email', self.value)]

class EmailSubjectObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_SUBJECT, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_available_actions(self):
        return []

class YaraRuleObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_YARA_RULE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_available_actions(self):
        return []

class IndicatorObservable(Observable):
    def __init__(self, *args, **kwargs):
        self._sip_details = None
        self._cbc_ioc_details = None
        super().__init__(F_INDICATOR, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_template_path(self):
        return "analysis/indicator_observable.html"

    @property
    def jinja_available_actions(self):
        result = []
    
        # SIP indicators start with sip:
        if self.is_sip_indicator:
            result.append(ObservableActionSetSIPIndicatorStatus_Informational())
            result.append(ObservableActionSetSIPIndicatorStatus_New())
            result.append(ObservableActionSetSIPIndicatorStatus_Analyzed())

        # CBC indicators
        elif self.is_cbc_ioc:
            if not self.is_cbc_query_ioc:
                # Query based IOCs should be tuned.
                # equality or regex IOCs can be turned off/on.
                result.append(ObservableActionSetCBC_IOC_StatusActive())
                result.append(ObservableActionSetCBC_IOC_StatusIgnore())

        return result

    @property
    def is_sip_indicator(self):
        return self.value.startswith('sip:')

    @property
    def sip_details(self):
        if self._sip_details is not None:
            return self._sip_details

        if not self.is_sip_indicator:
            return None

        try:
            self._sip_details = query_sip_indicator(int(self.value[len('sip:'):]))
            return self._sip_details
        except Exception as e:
            logging.error(f"unable to obtain SIP indicator details for {self.value}: {e}")
            return None

    @property
    def sip_status(self):
        if not self.is_sip_indicator:
            return None

        if self.sip_details is None:
            return None

        return self.sip_details['status']

    @property
    def is_cbc_ioc(self):
        if self.value.startswith('cbc:'):
            if '/' not in self.value:
                logging.warning(f"{self.value} not correctly formatted as cbc:report_id/ioc_id")
                return False
            return True
        return False

    @property
    def cbc_ioc_details(self):
        if not self.is_cbc_ioc:
            return None
        if not self._cbc_ioc_details:
            self._cbc_ioc_details = get_cbc_ioc_details(self.value)
        return self._cbc_ioc_details

    @property
    def is_cbc_query_ioc(self):
        if not self.is_cbc_ioc:
            return None
        if not self.cbc_ioc_details:
            return None
        ioc_type = self.cbc_ioc_details.get('match_type')
        if ioc_type == "query":
            return True
        return False

    @property
    def cbc_ioc_status(self):
        "Ignored OR Active?"
        if not self.is_cbc_ioc:
            return None
        return get_cbc_ioc_status(self.value)


class MD5Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MD5, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        if self.value.count('0') == len(self.value):
            raise ObservableValueError(f"invalid MD5 {self.value}")

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class SHA1Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SHA1, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        if self.value.count('0') == len(self.value):
            raise ObservableValueError(f"invalid SHA1 {self.value}")

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class SHA256Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SHA256, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        if self.value.count('0') == len(self.value):
            raise ObservableValueError(f"invalid SHA256 {self.value}")

    @property
    def jinja_template_path(self):
        return "analysis/sha256_observable.html"

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class EmailConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        self._mail_from = None
        self._rcpt_to = None
        super().__init__(F_EMAIL_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        self._mail_from, self._rcpt_to = parse_email_conversation(self.value)

    @property
    def mail_from(self):
        return self._mail_from

    @property
    def rcpt_to(self):
        return self._rcpt_to

    @property
    def jinja_template_path(self):
        return "analysis/email_conversation_observable.html"

class SnortSignatureObservable(Observable):
    def __init__(self, *args, **kwargs):
        self.signature_id = None
        self.rev = None
        super().__init__(F_SNORT_SIGNATURE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        _ = self.value.split(':')
        if len(_) == 3:
            _, self.signature_id, self.rev = _
        else:
            logging.warning(f"unexpected snort/suricata signature format: {self.value}")

class MessageIDObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MESSAGE_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = normalize_message_id(new_value.strip())

    @property
    def remediation_targets(self):
        message_id = html.unescape(self.value)

        # create targets from recipients of message_id in email archive
        targets = {}
        with get_db_connection("email_archive") as db:
            c = db.cursor()
            sql = (
                "SELECT as1.value FROM archive_search as1 "
                "JOIN archive_search as2 ON as1.archive_id = as2.archive_id "
                "WHERE as2.field = 'message_id' AND as2.value = %s AND as1.field IN ('env_to', 'body_to')"
            )
            c.execute(sql, (message_id,))
            for row in c:
                target = create_email_delivery(message_id, row[0].decode('utf-8'))
                if target not in targets:
                    targets[target] = RemediationTarget('email', target)

        # also get targets from remediation history
        query = saq.db.query(Remediation)
        query = query.filter(Remediation.type == 'email')
        query = query.filter(Remediation.key.like(f"{message_id}%"))
        history = query.all()
        for h in history:
            if h.key not in targets:
                targets[h.key] = RemediationTarget('email', h.key)

        return list(targets.values())

class ProcessGUIDObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        super().__init__(F_PROCESS_GUID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class ExternalUIDObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        self._tool = None
        self._uid = None
        super().__init__(F_EXTERNAL_UID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        self._tool, self._uid = self.value.split(':', 1)

    @property
    def tool(self):
        return self._tool

    @property
    def uid(self):
        return self._uid

class DLPIncidentObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        super().__init__(F_DLP_INCIDENT, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = []
        result.append(ObservableActionViewInDLP())
        result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result

class ExabeamSessionObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        super().__init__(F_EXABEAM_SESSION, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = []
        result.append(ObservableActionViewInExabeamSession())
        result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result

class O365FileObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        super().__init__(F_O365_FILE, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = []
        result.append(ObservableActionDownloadO365File())
        result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result

    @property
    def remediation_targets(self):
        return [RemediationTarget('o365_file', self.value)]

class FireEyeUUIDObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        super().__init__(F_FIREEYE_UUID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class TestObservable(Observable):
    __test__ = False # tell pytest this is not a test class
    def __init__(self, *args, **kwargs): 
        super().__init__(F_TEST, *args, **kwargs)

    # this allows us to use any object we want for the observable value
    # useful for passing around parameters for testing
    @property
    def value(self):
        return pickle.loads(base64.b64decode(self._value))

    @value.setter
    def value(self, v):
        self._value = base64.b64encode(pickle.dumps(v))

RE_MAC = re.compile(r'^([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?$')
class MacAddressObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MAC_ADDRESS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value

        # try to deal with the various formats of mac addresses
        # some separate with different characters and some don't separate at all
        m = RE_MAC.match(new_value)
        if m is None:
            raise ObservableValueError(f"{new_value} does not parse as a mac address")

        self.mac_parts = m.groups()

    def mac_address(self, sep=':'):
        """Return the mac address formatted with the given separator. Defaults to :"""
        return sep.join(self.mac_parts)
#
# technically we could store the class and module inside the observable
# and load it at runtime by reading that and doing it the same way we load analysis modules
# the problem is that sometimes you need to specify observables by textual type and value
# for example, when running from the command line, and when receiving new alerts over the wire
# thus we keep this mapping around
#

_OBSERVABLE_TYPE_MAPPING = {
    F_ASSET: AssetObservable,
    F_DLP_INCIDENT: DLPIncidentObservable,
    F_EMAIL_ADDRESS: EmailAddressObservable,
    F_EMAIL_CONVERSATION: EmailConversationObservable,
    F_EMAIL_DELIVERY: EmailDeliveryObservable,
    F_EMAIL_SUBJECT: EmailSubjectObservable,
    F_EXABEAM_SESSION: ExabeamSessionObservable,
    F_EXTERNAL_UID: ExternalUIDObservable,
    F_FILE: FileObservable,
    F_FILE_LOCATION: FileLocationObservable,
    F_FILE_NAME: FileNameObservable,
    F_FILE_PATH: FilePathObservable,
    F_FIREEYE_UUID: FireEyeUUIDObservable,
    F_FQDN: FQDNObservable,
    F_HOSTNAME: HostnameObservable,
    F_INDICATOR: IndicatorObservable,
    F_IPV4: IPv4Observable,
    F_IPV4_CONVERSATION: IPv4ConversationObservable,
    F_IPV4_FULL_CONVERSATION: IPv4FullConversationObservable,
    F_MAC_ADDRESS: MacAddressObservable,
    F_MD5: MD5Observable,
    F_MESSAGE_ID: MessageIDObservable,
    F_O365_FILE: O365FileObservable,
    F_PCAP: FileObservable,
    F_PROCESS_GUID: ProcessGUIDObservable,
    F_SHA1: SHA1Observable,
    F_SHA256: SHA256Observable,
    F_SNORT_SIGNATURE: SnortSignatureObservable,
    F_SUSPECT_FILE: FileObservable,
    F_TEST: TestObservable,
    F_URL: URLObservable,
    F_USER: UserObservable,
    F_YARA_RULE: YaraRuleObservable,
}

def create_observable(o_type, o_value, o_time=None):
    """Returns an Observable-based class instance for the given type, value and optionally time, 
       or None if value is invalid for the type of Observable."""

    o_class = None

    try:
        o_class = _OBSERVABLE_TYPE_MAPPING[o_type]
    except KeyError:
        logging.debug("unknown observable type {}".format(o_type))

    try:
        if o_class is None:
            return DefaultObservable(o_type, o_value, time=o_time)
        else:
            return o_class(o_value, time=o_time)
    except ObservableValueError as e:
        logging.debug("invalid value {} for observable type {}: {}".format(o_value.encode('unicode_escape'), o_type, e))
        return None
