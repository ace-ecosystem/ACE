# vim: sw=4:ts=4:et

import logging
import unittest

import saq

from saq.crypto import *
from saq.configuration import *
from saq.test import *

class TestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        set_encryption_password('test')

    def test_encrypt_decrypt_delete_password(self):
        encrypt_password('password', 'Hello, World!')
        self.assertEquals(decrypt_password('password'), 'Hello, World!')
        self.assertEquals(delete_password('password'), 1)
        self.assertIsNone(decrypt_password('password'))

    @unittest.skip("no longer throws exception")
    def test_no_decryption_key(self):
        encrypt_password('password', 'Hello, World!')
        saq.ENCRYPTION_PASSWORD = None
        with self.assertRaises(EncryptedPasswordError):
            decrypt_password('password')

    def test_encrypted_password_config(self):
        encrypt_password('proxy.password', 'unittest')
        saq.CONFIG['proxy']['password'] = 'encrypted:proxy.password'
        self.assertEquals(saq.CONFIG['proxy']['password'], 'unittest')

    @unittest.skip("no longer throws exception")
    def test_encrypted_password_config_no_decryption_key(self):
        encrypt_password('proxy.password', 'unittest')
        saq.CONFIG['proxy']['password'] = 'encrypted:proxy.password'
        saq.ENCRYPTION_PASSWORD = None
        with self.assertRaises(EncryptedPasswordError):
            self.assertEquals(saq.CONFIG['proxy']['password'], 'unittest')
