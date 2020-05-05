# vim: sw=4:ts=4:et

import json
import re
import logging
from ldap3 import Server, Connection, SIMPLE, SYNC, SUBTREE, ALL, ALL_ATTRIBUTES
import saq

def query(query):
    enabled = saq.CONFIG.getboolean('ldap', 'enabled')
    server = saq.CONFIG.get('ldap', 'ldap_server')
    port = saq.CONFIG.getint('ldap', 'ldap_port') or 389
    user = saq.CONFIG.get('ldap', 'ldap_bind_user')
    password = saq.CONFIG.get('ldap', 'ldap_bind_password')
    base_dn = saq.CONFIG.get('ldap', 'ldap_base_dn')

    if not enabled:
        return []

    try:
        logging.debug(f"connecting to ldap server {server} on port {port}")
        with Connection(Server(server, port=port, get_info=ALL), auto_bind=True, client_strategy=SYNC, user=user, password=password, authentication=SIMPLE, check_names=True) as c:
            logging.debug(f"running ldap query ({query})")
            c.search(base_dn, f"({query})", SUBTREE, attributes=ALL_ATTRIBUTES)

            # convert result to json
            response = json.loads(c.response_to_json())
            result = c.result

            if len(response['entries']) > 0:
                return response['entries']
            return []

    except Exception as e:
        logging.warning(f"ldap query failed {query}: {e}")
        return []

def lookup_email_address(email_address):
    m = re.match(r'^<?([^>]+)>?$', email_address.strip())
    email = m.group(1)
    if saq.CONFIG.getboolean('ldap', 'on_prem_lookup_enabled', fallback=False):
        name, domain = email.split('@', 1)
        internal = f"{name}@{saq.CONFIG['ldap']['on_prem_lookup_domain']}"
        return saq.ldap.query(f"|(mail={email})(mail={internal})")
    return saq.ldap.query(f"mail={email}")
