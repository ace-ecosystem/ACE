from dataclasses import dataclass
from typing import Union, Optional
import hashlib
import io
import os, os.path

from saq.system import ACESystemInterface
from saq.system.storage import StorageInterface, ContentMetadata

class ThreadedStorageInterface(ACESystemInterface):

    #
    # simple storage interface that stores everything in memory
    #

    content = {} # key = sha256 hash, value = ContentMetadata
    data = {} # key = sha256 hash, value = bytes

    def store_content(self, content: Union[bytes, str, io.IOBase], meta: ContentMetadata) -> str:
        # if this is a string then just convert it into utf-8
        if isinstance(content, str):
            data = content.encode()
        elif isinstance(content, io.IOBase):
            # TODO calculate sha2 as we go
            stream = content
            data = io.BytesIO()
            while True:
                _buffer = content.read(io.DEFAULT_BUFFER_SIZE)
                if not _buffer:
                    break

                data.write(_buffer)

            data = data.getvalue()
        elif isinstance(content, bytes):
            data = content
        else:
            raise TypeError(f"unsupported content type {type(content)}")

        m = hashlib.sha256()
        m.update(data)
        sha256 = m.hexdigest().lower()

        meta.size = len(data)
        meta.sha256 = sha256
        self.content[sha256] = meta
        self.data[sha256] = data

        return sha256

    def get_content_meta(self, sha256: str) -> Union[ContentMetadata, None]:
        return self.content.get(sha256)

    def get_content_bytes(self, sha256: str) -> Union[bytes, None]:
        return self.data.get(sha256)

    def get_content_stream(self, sha256: str) -> Union[io.IOBase, None]:
        data = self.data.get(sha256)
        if data is None:
            return None

        return io.BytesIO(data)

    def delete_content(self, sha256: str) -> bool:
        content = self.content.pop(sha256, None)
        data = self.data.pop(sha256, None)

        if content:
            return True

        if data:
            return True

        return False

    def reset(self):
        self.content = {}
        self.data = {}
