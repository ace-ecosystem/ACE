import json
import re
import logging
from ldap3.core import exceptions
from ldap3.utils.conv import escape_filter_chars
from ldap3 import Server, Connection, SIMPLE, RESTARTABLE, SUBTREE, ALL, ALL_ATTRIBUTES
from ldap3.utils.ciDict import CaseInsensitiveDict
import saq
import saq.email

connection = None
def connect():
    global connection
    connection = Connection(
        Server(
            saq.CONFIG['ldap']['ldap_server'],
            port = saq.CONFIG['ldap'].getint('ldap_port', fallback=389), 
            get_info = ALL,
        ),
        auto_bind = True,
        client_strategy = RESTARTABLE,
        user = saq.CONFIG['ldap']['ldap_bind_user'],
        password = saq.CONFIG['ldap']['ldap_bind_password'],
        authentication = SIMPLE,
        check_names = True,
    )

def search(query, attributes=ALL_ATTRIBUTES):
    # replace memberOf wildcard queries with fullmatch
    query = re.sub(r'\(memberOf=([^\)]*\*[^\)]*)\)', member_of_wildcard_substitute, query)
    base_dn = saq.CONFIG['ldap']['ldap_base_dn']
    if connection is None:
        connect()
    return [entry_to_dict(e) for e in list(connection.extend.standard.paged_search(base_dn, query, SUBTREE, attributes=attributes))]

# custom encoder for the annoying dict type that comes out of ldap3
class CaseInsensitiveDictEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, CaseInsensitiveDict):
            return dict(obj)
        if isinstance(obj, bytes):
            return str(obj)[2:-1]
        try:
            return json.JSONEncoder.default(self, obj)
        except:
            return str(obj)

# hack to make ldap3 paged_search results json serializable
def entry_to_dict(entry):
    return json.loads(json.dumps(entry, cls=CaseInsensitiveDictEncoder))

# return list of entries that match a given email address
def lookup_email_address(email_address):
    # don't look up external emails
    if not saq.email.is_local_email_domain(email_address):
        return []

    # lookup the user for an email by name so that it will match various internal domains
    email = saq.email.normalize_email_address(email_address)
    name, domain = email.split('@', 1)
    name = escape_filter_chars(name)
    return search(f"(mail={name}@*)")

# lookup a user by cn and return the attributes including manager cn
def lookup_user(user):
    user = escape_filter_chars(user)
    entries = search(f"(cn={user})")
    if len(entries) == 0:
        return None
    attributes = entries[0]['attributes']
    if 'manager' in attributes:
        m = re.match(r'CN=([^,]+)', attributes['manager'])
        attributes['manager_cn'] = m.group(1)
    return attributes

def lookup_hostname(hostname):
    return lookup_user(hostname)

def get_child_groups(groups):
    query = ""
    for group in groups:
        query += f"(memberOf={group['dn']})"
    child_groups = search(f"(&(objectCategory=group)(|{query}))")
    if len(child_groups) > 0:
        child_groups.extend(get_child_groups(child_groups))
    return child_groups

def member_of_wildcard_substitute(match):
    query = f"(&(objectCategory=group)(cn={match.group(1)}))"
    groups = search(query)
    groups.extend(get_child_groups(groups))
    query = ""
    for group in groups:
        query += f"(memberOf={group['dn']})"
    return query

def find_users(query):
    entries = search(query, attributes=['cn'])
    return [e['attributes']['cn'].lower() for e in entries]

# converts a list of user ids to email addresses
def lookup_emails(employees):
    if len(employees) == 0:
        return []
    emps = ''.join([ f'(mail={e})' for e in employees ])
    query = f'(&(objectCategory=user)(|{emps}))'
    entries = search(query, attributes=['cn'])
    return [e['attributes']['cn'].lower() for e in entries]
