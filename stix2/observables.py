"""STIX 2.0 Cyber Observable Objects"""

from .base import Observable
# from .properties import (BinaryProperty, BooleanProperty, DictionaryProperty,
#                          HashesProperty, HexProperty, IDProperty,
#                          IntegerProperty, ListProperty, ReferenceProperty,
#                          StringProperty, TimestampProperty, TypeProperty)
from .properties import BinaryProperty, HashesProperty, StringProperty, TypeProperty


class Artifact(Observable):
    _type = 'artifact'
    _properties = {
        'type': TypeProperty(_type),
        'mime_type': StringProperty(),
        'payload_bin': BinaryProperty(),
        'url': StringProperty(),
        'hashes': HashesProperty(),
    }


class File(Observable):
    _type = 'file'
    _properties = {
        'type': TypeProperty(_type),
    }
