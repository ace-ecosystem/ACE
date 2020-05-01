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

    def test_crud_database_config_str(self):
        # test set
        set_database_config_value('test', 'test_value')
        self.assertEquals(get_database_config_value('test'), 'test_value')
        # test update
        set_database_config_value('test', 'test_value_2')
        self.assertEquals(get_database_config_value('test'), 'test_value_2')
        # test delete
        delete_database_config_value('test')
        self.assertIsNone(get_database_config_value('test'))

    def test_crud_database_config_int(self):
        # test set
        set_database_config_value('test', 1)
        self.assertEquals(get_database_config_value('test', int), 1)
        # test update
        set_database_config_value('test', 2)
        self.assertEquals(get_database_config_value('test', int), 2)
        # test delete
        delete_database_config_value('test')
        self.assertIsNone(get_database_config_value('test', int))

    def test_crud_database_config_bytes(self):
        # test set
        set_database_config_value('test', b'test_value')
        self.assertEquals(get_database_config_value('test', bytes), b'test_value')
        # test update
        set_database_config_value('test', b'test_value_2')
        self.assertEquals(get_database_config_value('test', bytes), b'test_value_2')
        # test delete
        delete_database_config_value('test')
        self.assertIsNone(get_database_config_value('test'))

    def test_database_config_invalid_type(self):
        with self.assertRaises(TypeError):
            set_database_config_value('test', 1.0) # float not supported

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
        self.assertEquals(saq.CONFIG['proxy'].get('password'), 'unittest')

    @unittest.skip("no longer throws exception")
    def test_encrypted_password_config_no_decryption_key(self):
        encrypt_password('proxy.password', 'unittest')
        saq.CONFIG['proxy']['password'] = 'encrypted:proxy.password'
        saq.ENCRYPTION_PASSWORD = None
        with self.assertRaises(EncryptedPasswordError):
            self.assertEquals(saq.CONFIG['proxy']['password'], 'unittest')
