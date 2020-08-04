#!/usr/bin/env python3
#
# initializes your docker development environment by creating
# random passwords for the database connections
# and then updating the configuration files with those passwords
#

import os
import os.path
import random
import re
import shutil
import string

def generate_password() -> str:
    return ''.join(random.choices(string.ascii_letters, k=random.randint(23, 32))) 

def main(): 
    user_password = generate_password()
    source_path = os.path.join('sql', 'templates', 'create_db_user.sql')
    target_path = os.path.join('sql', '70-create-db-user.sql')
    with open(source_path, 'r') as fp_in:
        sql = fp_in.read().replace('ACE_DB_USER_PASSWORD', user_password)
        with open(target_path, 'w') as fp:
            fp.write(sql)

        print(f"created {target_path}")

    target_path = os.path.join('sql', 'templates', 'create_db_user.sql')
    with open(target_path, 'r') as fp_in:
        sql = fp_in.read().replace('ACE_DB_USER_PASSWORD', user_password)
        with open(os.path.join('sql', '70-create-db-user.sql'), 'w') as fp:
            fp.write(sql)

        print(f"created {target_path}")

    target_path = os.path.join('docker', 'provision', 'ace', 'etc', 'mysql_defaults')
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, 'w') as fp:
        fp.write(f"""[client]
host=ace-db
user=ace-user
password={user_password}""")

    print(f"created {target_path}")

    admin_password = generate_password()
    target_path = os.path.join('sql', 'templates', 'create_db_super_user.sql')
    with open(target_path, 'r') as fp_in:
        sql = fp_in.read().replace('ACE_SUPERUSER_DB_USER_PASSWORD', admin_password)
        with open(os.path.join('sql', '71-create-db-super-user.sql'), 'w') as fp:
            fp.write(sql)

    print(f"created {target_path}")

    target_path = os.path.join('docker', 'provision', 'ace', 'etc', 'mysql_defaults.root')
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, 'w') as fp:
        fp.write(f"""[client]
host=ace-db
user=ace-superuser
password={admin_password}""")

    print(f"created {target_path}")

    target_path = os.path.join('docker', 'provision', 'ace', 'etc', 'saq.docker.passwords.ini')
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, 'w') as fp:
        fp.write(f"""
[database_ace]
password = {user_password}

[database_collection]
password = {user_password}

[database_email_archive]
password = {user_password}

[database_brocess]
password = {user_password}

[database_vt_hash_cache]
password = {user_password}""")

    print(f"created {target_path}")

    for src_sql, dest_sql in [
        ('01-ace.sql', '21-ace-unittest.sql'),
        ('02-email-archive.sql', '22-email-archive-unittest.sql'),
        ('03-brocess.sql', '23-brocess-unittest.sql'),
        ('04-vt-hash-cache.sql', '24-vt-hash-cache-unittest.sql'),
        ('05-amc.sql', '25-amc-unittest.sql'), ]:
        with open(os.path.join('sql', src_sql), 'r') as fp_in:
            with open(os.path.join('sql', dest_sql), 'w') as fp_out:
                for line in fp_in:
                    if line.startswith('CREATE DATABASE IF NOT EXISTS `') \
                    or line.startswith('ALTER DATABASE `') \
                    or line.startswith('USE `'):
                        line = re.sub(r'`([^`]+)`', r'`\1-unittest`', line)

                    fp_out.write(line)

    # this sucks -- a few of the integration tests require yet another ace database
    # XXX fix me!
    for src_sql, dest_sql in [
        ('01-ace.sql', '211-ace-unittest-2.sql'), ]:
        with open(os.path.join('sql', src_sql), 'r') as fp_in:
            with open(os.path.join('sql', dest_sql), 'w') as fp_out:
                for line in fp_in:
                    if line.startswith('CREATE DATABASE IF NOT EXISTS `') \
                    or line.startswith('ALTER DATABASE `') \
                    or line.startswith('USE `'):
                        line = re.sub(r'`([^`]+)`', r'`\1-unittest-2`', line)

                    fp_out.write(line)

if __name__ == '__main__':
    main()
