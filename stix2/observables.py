"""STIX 2.0 Cyber Observable Objects"""

from .base import Observable
# from .properties import (BinaryProperty, BooleanProperty, DictionaryProperty,
#                          HashesProperty, HexProperty, IDProperty,
#                          IntegerProperty, ListProperty, ReferenceProperty,
#                          StringProperty, TimestampProperty, TypeProperty)
from .properties import BinaryProperty, HashesProperty, IntegerProperty, StringProperty, TypeProperty


class Artifact(Observable):
    _type = 'artifact'
    _properties = {
        'type': TypeProperty(_type),
        'mime_type': StringProperty(),
        'payload_bin': BinaryProperty(),
        'url': StringProperty(),
        'hashes': HashesProperty(),
    }


class AutonomousSystem(Observable):
    _type = 'autonomous-system'
    _properties = {
        'type': TypeProperty(_type),
        'number': IntegerProperty(),
        'name': StringProperty(),
        'rir': StringProperty(),
    }


class File(Observable):
    _type = 'file'
    _properties = {
        'type': TypeProperty(_type),
    }
