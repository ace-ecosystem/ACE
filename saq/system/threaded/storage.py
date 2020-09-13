from dataclasses import dataclass
from typing import Union, Optional
import hashlib
import io
import os, os.path

from saq.system import ACESystemInterface
from saq.system.storage import StorageInterface, Content, ContentMetadata

class ThreadedContent(Content):
    @property
    def stream(self) -> Union[io.IOBase, None]:
        if self.data is None:
            return None

        return io.BytesIO(self.data)

    @stream.setter
    def stream(self, value):
        pass

class ThreadedStorageInterface(ACESystemInterface):

    content = {} # key = sha256 hash, value = ThreadedContent

    def store_content(self, content: Union[bytes, str, io.IOBase], meta: Optional[ContentMetadata] = None) -> str:
        meta = meta or ContentMetadata()
        # the content is also stored on the file system in the location specified
        file_fp = None
        if meta.location:
            file_fp = open(meta.location, 'wb')

        # if this is a string then just convert it into utf-8
        if isinstance(content, str):
            data = content.encode()
            if file_fp:
                file_fp.write(data)
        elif isinstance(content, io.IOBase):
            stream = content
            data = io.BytesIO()
            while True:
                _buffer = content.read(io.DEFAULT_BUFFER_SIZE)
                if not _buffer:
                    break

                data.write(_buffer)
                if file_fp:
                    file_fp.write(_buffer)

            data = data.getvalue()
        else:
            data = content
            if file_fp:
                file_fp.write(data)

        if file_fp:
            file_fp.close()

        m = hashlib.sha256()
        m.update(data)
        sha256 = m.hexdigest().lower()

        meta.size = len(data)
        meta.sha256 = sha256
        self.content[sha256] = ThreadedContent(data=data, stream=None, meta=meta)

        return sha256

    def get_content(self, sha256: str) -> Union[Content, None]:
        return self.content.get(sha256)

    def reset(self):
        for sha256, content in self.content.items():
            if content.meta.location:
                os.remove(content.meta.location)

        self.content = {}
