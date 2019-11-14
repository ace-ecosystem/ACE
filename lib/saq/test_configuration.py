# vim: sw=4:ts=4:et

import logging

import saq

from saq.crypto import *
from saq.configuration import *
from saq.test import *

class TestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.old_password = saq.ENCRYPTION_PASSWORD
        saq.ENCRYPTION_PASSWORD = get_aes_key('test')

    def tearDown(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        saq.ENCRYPTION_PASSWORD = self.old_password

    def test_store_encrypted_password(self):
        store_encrypted_password('proxy', 'password', 'unittest')
        self.assertTrue(os.path.exists(encrypted_password_db_path()))
        p = get_encrypted_passwords()
        self.assertEquals(p['proxy.password'], 'unittest')

    def test_encrypted_password_config(self):
        store_encrypted_password('proxy', 'password', 'unittest')
        load_configuration()
        saq.CONFIG.load_encrypted_passwords()
        self.assertEquals(saq.CONFIG['proxy']['password'], 'unittest')

    def test_encrypted_password_config_no_decryption_key(self):
        store_encrypted_password('proxy', 'password', 'unittest')
        saq.ENCRYPTION_PASSWORD = None
        load_configuration()
        saq.CONFIG.load_encrypted_passwords()
        with self.assertRaises(RuntimeError):
            self.assertEquals(saq.CONFIG['proxy']['password'], None)

    def test_delete_encrypted_password(self):
        store_encrypted_password('proxy', 'password', 'unittest')
        load_configuration()
        saq.CONFIG.load_encrypted_passwords()
        self.assertEquals(saq.CONFIG['proxy']['password'], 'unittest')
        delete_encrypted_password('proxy', 'password')
        load_configuration()
        saq.CONFIG.load_encrypted_passwords()
        self.assertEquals(saq.CONFIG['proxy']['password'], '')
