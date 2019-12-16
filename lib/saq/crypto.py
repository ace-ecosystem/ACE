# vim: sw=4:ts=4:et:cc=120
#
# cryptography functions used by ACE
#

import io
import logging
import os.path
import random
import socket
import struct

import Crypto.Random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

import saq
from saq.service import ACEService
from saq.util import create_directory

CHUNK_SIZE = 64 * 1024

class PasswordNotSetError(Exception):
    """Thrown when an attempt is made to load the encryption key but it has not been set."""
    pass

class InvalidPasswordError(Exception):
    """Thrown when an invalid password is provided."""
    pass

def read_ecs():
    """Reads the encryption password from the encryption cache service. Returns None if the service is unavailable."""
    try:
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.settimeout(3)
        client_socket.connect(saq.ECS_SOCKET_PATH)
        return client_socket.recv(4096).decode('utf8').strip()
    except Exception as e:
        logging.debug(f"unable to read from ecs: {e}")
        return None
    finally:
        try:
            client_socket.close()
        except:
            pass

def get_encryption_store_path():
    """Returns the path to the directory that contains the encryption keys and meta data."""
    return os.path.join(saq.DATA_DIR, saq.CONFIG['encryption']['encryption_store_path'])

def encryption_key_set():
    """Returns True if the encryption key has been set, False otherwise."""
    if not os.path.isdir(get_encryption_store_path()):
        return False

    return os.path.exists(os.path.join(get_encryption_store_path(), 'key')) \
           and os.path.exists(os.path.join(get_encryption_store_path(), 'salt')) \
           and os.path.exists(os.path.join(get_encryption_store_path(), 'verification')) \
           and os.path.exists(os.path.join(get_encryption_store_path(), 'iterations'))

def get_decryption_key(password):
    """Returns the 32 byte key used to decrypt the encryption key.
       Raises InvalidPasswordError if the password is incorrect.
       Raises PasswordNotSetError if the password has not been set."""

    if not encryption_key_set():
        raise PasswordNotSetError()

    # the salt and iterations used are stored when we set the password
    with open(os.path.join(get_encryption_store_path(), 'salt'), 'rb') as fp:
        salt = fp.read()

    with open(os.path.join(get_encryption_store_path(), 'iterations'), 'r') as fp:
        iterations = int(fp.read())

    with open(os.path.join(get_encryption_store_path(), 'verification'), 'rb') as fp:
        target_verification = fp.read()

    result = PBKDF2(password, salt, 64, iterations)
    if target_verification != result[32:]:
        raise InvalidPasswordError()

    return result[:32]

def get_aes_key(password):
    """Returns the 32 byte system encryption key."""
    decryption_key = get_decryption_key(password)
    with open(os.path.join(get_encryption_store_path(), 'key'), 'rb') as fp:
        encrypted_key = fp.read()

    return decrypt_chunk(encrypted_key, decryption_key)

def set_encryption_password(password, old_password=None, key=None):
    """Sets the encryption password for the system. If a password has already been set, then
       old_password can be provided to change the password. Otherwise, the old password is
       over-written by the new password.
       If the key parameter is None then the PRIMARY AES KEY is random. Otherwise, the given key is used.
       The default of a random key is fine."""
    assert isinstance(password, str)
    assert old_password is None or isinstance(old_password, str)
    assert key is None or (isinstance(key, bytes) and len(key) == 32)

    # has the encryption password been set yet?
    if encryption_key_set():
        # did we provide a password for it?
        if old_password is not None:
            # get the existing encryption password
            saq.ENCRYPTION_PASSWORD = get_aes_key(old_password)
    else:
        # otherwise we just make a new one
        if key is None:
            saq.ENCRYPTION_PASSWORD = Crypto.Random.OSRNG.posix.new().read(32)
        else:
            saq.ENCRYPTION_PASSWORD = key

    # now we compute the key to use to encrypt the encryption key using the user-supplied password
    salt = Crypto.Random.OSRNG.posix.new().read(saq.CONFIG['encryption'].getint('salt_size', fallback=32))
    iterations =  saq.CONFIG['encryption'].getint('iterations', fallback=8192)
    result = PBKDF2(password, salt, 64, iterations)
    user_encryption_key = result[:32] # the first 32 bytes is the user encryption key
    verification_key = result[32:] # and the second 32 bytes is used for password verification

    create_directory(get_encryption_store_path())

    with open(os.path.join(get_encryption_store_path(), 'verification'), 'wb') as fp:
        fp.write(verification_key)

    encrypted_encryption_key = encrypt_chunk(saq.ENCRYPTION_PASSWORD, password=user_encryption_key)
    with open(os.path.join(get_encryption_store_path(), 'key'), 'wb') as fp:
        fp.write(encrypted_encryption_key)

    with open(os.path.join(get_encryption_store_path(), 'salt'), 'wb') as fp:
        fp.write(salt)

    with open(os.path.join(get_encryption_store_path(), 'iterations'), 'w') as fp:
        fp.write(str(iterations))

# https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
def encrypt(source_path, target_path, password=None):
    """Encrypts the given file at source_path with the given password and saves the results in target_path.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    encryptor = AES.new(password, AES.MODE_CBC, iv)
    file_size = os.path.getsize(source_path)

    with open(source_path, 'rb') as fp_in:
        with open(target_path, 'wb') as fp_out:
            fp_out.write(struct.pack('<Q', file_size))
            fp_out.write(iv)

            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                fp_out.write(encryptor.encrypt(chunk))

def encrypt_chunk(chunk, password=None):
    """Encrypts the given chunk of data and returns the encrypted chunk.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    encryptor = AES.new(password, AES.MODE_CBC, iv)

    original_size = len(chunk)

    if len(chunk) % 16 != 0:
        chunk += b' ' * (16 - len(chunk) % 16)

    result = struct.pack('<Q', original_size) + iv + encryptor.encrypt(chunk)
    return result

def decrypt(source_path, target_path=None, password=None):
    """Decrypts the given file at source_path with the given password and saves the results in target_path.
       If target_path is None then output will be sent to standard output.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    with open(source_path, 'rb') as fp_in:
        original_size = struct.unpack('<Q', fp_in.read(struct.calcsize('Q')))[0]
        iv = fp_in.read(16)
        decryptor = AES.new(password, AES.MODE_CBC, iv)

        with open(target_path, 'wb') as fp_out:
            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break

                fp_out.write(decryptor.decrypt(chunk))

            fp_out.truncate(original_size)

def decrypt_chunk(chunk, password=None):
    """Decrypts the given encrypted chunk with the given password and returns the decrypted chunk.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32


    _buffer = io.BytesIO(chunk)
    original_size = struct.unpack('<Q', _buffer.read(struct.calcsize('Q')))[0]
    iv = _buffer.read(16)
    chunk = _buffer.read()

    #original_size = struct.unpack('<Q', chunk[0:struct.calcsize('Q')])[0]
    #iv = chunk[struct.calcsize('Q'):struct.calcsize('Q') + 16]
    #chunk = chunk[struct.calcsize('Q') + 16:]
    decryptor = AES.new(password, AES.MODE_CBC, iv)
    result = decryptor.decrypt(chunk)
    return result[:original_size]

class EncryptionCacheService(ACEService):
    def __init__(self, *args, **kwargs):
        if saq.ENCRYPTION_PASSWORD_PLAINTEXT is None:
            raise RuntimeError("missing password -- make sure you use the -p option")

        super().__init__(service_config=saq.CONFIG['service_ecs'], 
                         *args, **kwargs)

    def initialize_service_environment(self):
        if os.path.exists(saq.ECS_SOCKET_PATH):
            os.remove(saq.ECS_SOCKET_PATH)

    def execute_service(self):
        logging.info(f"starting encryption cache service on {saq.ECS_SOCKET_PATH}")
        while not self.is_service_shutdown:
            try:
                if os.path.exists(saq.ECS_SOCKET_PATH):
                    os.remove(saq.ECS_SOCKET_PATH)

                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.settimeout(1)
                server.bind(saq.ECS_SOCKET_PATH)
                server.listen(5)

                os.chmod(saq.ECS_SOCKET_PATH, 0o600)

                while not self.is_service_shutdown:
                    #logging.debug("waiting for next connection")
                    try:
                        client_socket, address = server.accept()
                        logging.debug("sending password")
                        client_socket.send(f'{saq.ENCRYPTION_PASSWORD_PLAINTEXT}\n'.encode('utf8'))
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"error handling client: {e}")
                    finally:
                        try:
                            #logging.debug("closing client connection")
                            client_socket.close()
                        except:
                            pass

            except Exception as e:
                logging.error(f"uncaught exception: {e}")
                continue
            finally:
                try:
                    server.close()
                except:
                    pass

    def stop_service(self, *args, **kwargs):
        super().stop_service(*args, **kwargs)

        try:
            # trigger the loop iteration on the loop that is blocking on write
            # by causing a BrokenPipeError exception
            with open(saq.ECS_SOCKET_PATH, 'r') as fp:
                pass
        except:
            pass

    def cleanup_service(self):
        if os.path.exists(saq.ECS_SOCKET_PATH):
            try:
                os.remove(saq.ECS_SOCKET_PATH)
            except Exception as e:
                pass
