# vim: ts=4:sw=4:et:cc=120

import io
import datetime
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

@dataclass
class Content:

    # NOTE 
    # The idea here is that you can just grab the data out of the data property
    # if it's small. Otherwise you read it out of the stream.  Subclasses will
    # have to implement the logic of when to use what and what kind of stream
    # is actually used.

    # the raw data as a bytes variable
    # if this is None then the data must be read from the stream
    data: Union[bytes, None]
    # a stream for reading the raw data
    # this must always be available
    stream: io.IOBase
    # the meta data for this content
    meta: ContentMetadata

#
# how things are actually stored is abstracted away by this interface
# content is referenced by the sha256 of the data in hex string format
#

class StorageInterface(ACESystemInterface):
    def store_content(self, content: Union[bytes, str, io.IOBase], meta: ContentMetadata) -> str:
        raise NotImplementedError()

    def get_content(self, sha256: str) -> Union[Content, None]:
        raise NotImplementedError()

def store_content(content: Union[bytes, str, io.IOBase], meta: ContentMetadata) -> str:
    return get_system().storage.store_content(content, meta)

def get_content(sha256: str) -> Union[Content, None]:
    return get_system().storage.get_content(sha256)
