import json
import re
from ldap3 import Server, Connection, SIMPLE, RESTARTABLE, SUBTREE, ALL, ALL_ATTRIBUTES
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

def search(query):
    if connection is None:
        connect()
    connection.search(saq.CONFIG['ldap']['ldap_base_dn'], query, SUBTREE, attributes=ALL_ATTRIBUTES)
    return json.loads(connection.response_to_json())['entries'] # XXX hack to have strings instead of lists of bytes for attributes

# return list of entires that match a given email address
def lookup_email_address(email_address):
    # don't look up external emails
    if not saq.email.is_local_email_domain(email_address):
        return []

    # lookup the user for an email by name so that it will match various internal domains
    email = saq.email.normalize_email_address(email_address)
    name, domain = email.split('@', 1)
    return search(f"(mail={name}@*)")

# lookup a user by cn and return the attributes including manager cn
def lookup_user(user):
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
