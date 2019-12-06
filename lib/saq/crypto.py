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

import saq
from saq.service import ACEService

CHUNK_SIZE = 64 * 1024

def _get_validation_hash_path():
    """Returns the full path to the file containing the encryption password validation hash."""
    return os.path.join(saq.SAQ_HOME, 'etc', 'validation_hash')

def _get_validation_hash():
    """Returns the validation hash of the encryption password, or None if it has not been set."""
    try:
        with open(_get_validation_hash_path(), 'r') as fp:
            return fp.read().strip().lower()
    except Exception as e:
        logging.warning("unable to load encryption password validation hash: {}".format(e))
        return None

def is_set():
    """Returns True if the encryption password has been set, False otherwise."""
    return _get_validation_hash() is not None

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

def _compute_validation_hash(password):
    assert isinstance(password, str)

    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(password.encode())
    initial_digest = h.digest()

    h = SHA256.new()
    h.update(initial_digest)
    return h.hexdigest().lower()

def test_encryption_password(password):
    """Tests the given password against what is saved in the global section of the config file as the encryption password.
       Returns True if the password is correct, False if it is incorrect or if the password is not set."""
    assert isinstance(password, str)

    validation_hash = _get_validation_hash()
    if validation_hash is None:
        return False
    
    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(password.encode())
    initial_digest = h.digest() # this would be the AES key

    h = SHA256.new()
    h.update(initial_digest)
    if h.hexdigest().lower() != validation_hash:
        return False

    return True

def set_encryption_password(password):
    """Sets the encryption password for the system by saving the validation hash."""
    assert isinstance(password, str)

    try:
        with open(_get_validation_hash_path(), 'w') as fp:
            fp.write(_compute_validation_hash(password))
        logging.info("updated validation hash")
    except Exception as e:
        logging.warning("unable to save encryption password validation hash: {}".format(e))

    # TODO if the password changed then we need to go through and reset all the encrypted configuration values

def get_aes_key(password):
    """Returns the binary key to be used to actually encrypt and decrypt."""
    assert isinstance(password, str)

    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(password.encode())
    return h.digest()

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
