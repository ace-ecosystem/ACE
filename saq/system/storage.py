# vim: ts=4:sw=4:et:cc=120

import contextlib
import datetime
import io
import os.path
import shutil

from dataclasses import dataclass, field
from typing import Union, Optional

from saq.system import ACESystemInterface, get_system

@dataclass
class ContentMetadata:
    # the meta "name" of the content
    # can be anything including the name of the file
    # additional information can be stored in the custom property
    name: str
    # the sha256 (lowercase hex) of the content
    sha256: str = None
    # the total size of the content (in bytes)
    size: int = 0
    # free-form "location" of the content (can be None if not used)
    # for example, on systems that store data locally this can be the path to the file
    # or on systems that store the data externally this can be the reference key to the content
    location: str = None
    # when the content was created (defaults to now)
    insert_date: datetime.datetime = field(default_factory=datetime.datetime.now)
    # when the content should be discarded (defaults to None which means never)
    expiration_date: Union[datetime.datetime, None] = None
    # dict for storing any required custom properties of the content
    custom: dict = field(default_factory=dict)


#
# how things are actually stored is abstracted away by this interface
# content is referenced by the sha256 of the data in hex string format
#

class StorageInterface(ACESystemInterface):
    def store_content(self, content: Union[bytes, str, io.IOBase], meta: ContentMetadata) -> str:
        raise NotImplementedError()

    def get_content_bytes(self, sha256: str) -> Union[bytes, None]:
        raise NotImplementedError()

    def get_content_stream(self, sha256: str) -> Union[io.IOBase, None]:
        raise NotImplementedError()

    def get_content_meta(self, sha256: str) -> Union[ContentMetadata, None]:
        raise NotImplementedError()

    def delete_content(self, sha256: str) -> bool:
        raise NotImplementedError()

def store_content(content: Union[bytes, str, io.IOBase], meta: ContentMetadata) -> str:
    return get_system().storage.store_content(content, meta)

def get_content_bytes(sha256: str) -> Union[bytes, None]:
    return get_system().storage.get_content_bytes(sha256)

def get_content_stream(sha256: str) -> Union[io.IOBase, None]:
    return get_system().storage.get_content_stream(sha256)

def get_content_meta(sha256: str) -> Union[ContentMetadata, None]:
    return get_system().storage.get_content_meta(sha256)

def delete_content(sha256: str) -> bool:
    return get_system().storage.delete_content(sha256)

#
# utility functions
#

def store_file(path: str, **kwargs) -> str:
    """Utility function that stores the contents of the given file and returns the sha2 hash."""
    assert isinstance(path, str)
    meta = ContentMetadata(path, **kwargs)
    with open(path, 'rb') as fp:
        return store_content(fp, meta)

def get_file(sha256: str, path: Optional[str]=None) -> bool:
    """Utility function that pulls data out of storage into a local file. The
    original path is used unless a target path is specified."""
    assert isinstance(sha256, str)
    assert path is None or isinstance(path, str)

    meta = get_content_meta(sha256)
    if meta is None:
        return False

    if path is None:
        path = meta.name

    with open(path, 'wb') as fp_out:
        with contextlib.closing(get_content_stream(sha256)) as fp_in:
            shutil.copyfileobj(fp_in, fp_out)

    return True
