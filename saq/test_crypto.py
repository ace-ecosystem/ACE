# vim: sw=4:ts=4:et

import logging

import saq

from saq.crypto import *
from saq.test import *

class TestCase(ACEBasicTestCase):

    #def setUp(self, *args, **kwargs):
        #super().setUp(*args, **kwargs)
        #self.old_password = saq.ENCRYPTION_PASSWORD
        #saq.ENCRYPTION_PASSWORD = get_aes_key('test')

    #def tearDown(self, *args, **kwargs):
        #super().setUp(*args, **kwargs)
        #saq.ENCRYPTION_PASSWORD = self.old_password

    def test_set_password(self):
        # ensure a password is not already set
        self.assertFalse(encryption_key_set())
        # set the new password
        set_encryption_password('test')
        self.assertTrue(encryption_key_set())
        # verify the password
        aes_key = get_aes_key('test')
        self.assertTrue(isinstance(aes_key, bytes))
        self.assertEquals(len(aes_key), 32)

        # encrypt and decrypt something with this password
        encrypted_chunk = encrypt_chunk('Hello, World!'.encode(), password=aes_key)
        self.assertEquals(decrypt_chunk(encrypted_chunk, password=get_aes_key('test')), 'Hello, World!'.encode())

    def test_change_password(self):
        # make sure that when we change the password we can still decrypt what we encrypted
        # ensure a password is not already set
        self.assertFalse(encryption_key_set())
        # set the new password
        set_encryption_password('test')
        self.assertTrue(encryption_key_set())
        # verify the password
        aes_key = get_aes_key('test')
        # now change the password to something else
        set_encryption_password('new password', old_password='test')
        # aes key should still be the same
        self.assertEquals(aes_key, get_aes_key('new password'))

    def test_invalid_password(self):
        self.assertFalse(encryption_key_set())
        # set the new password
        set_encryption_password('test')
        self.assertTrue(encryption_key_set())
        with self.assertRaises(InvalidPasswordError):
            aes_key = get_aes_key('invalid_password')

    def test_password_not_set(self):
        self.assertFalse(encryption_key_set())
        with self.assertRaises(PasswordNotSetError):
            aes_key = get_aes_key('test')
    
    def test_encrypt_chunk(self):
        set_encryption_password('test')
        chunk = b'1234567890'
        encrypted_chunk = encrypt_chunk(chunk)
        self.assertNotEquals(chunk, encrypted_chunk)
        decrypted_chunk = decrypt_chunk(encrypted_chunk)
        self.assertEquals(chunk, decrypted_chunk)

    def test_encrypt_empty_chunk(self):
        set_encryption_password('test')
        chunk = b''
        encrypted_chunk = encrypt_chunk(chunk)
        self.assertNotEquals(chunk, encrypted_chunk)
        decrypted_chunk = decrypt_chunk(encrypted_chunk)
        self.assertEquals(chunk, decrypted_chunk)
