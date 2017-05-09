"""STIX 2.0 Cyber Observable Objects

Embedded observable object types, such as Email MIME Component, which is
embedded in Email Message objects, inherit from _STIXBase instead of Observable
and do not have a '_type' attribute.
"""

from .base import _STIXBase, Observable
from .properties import (BinaryProperty, BooleanProperty, DictionaryProperty,
                         EmbeddedObjectProperty, HashesProperty,
                         IntegerProperty, ListProperty,
                         ObjectReferenceProperty, StringProperty,
                         TimestampProperty, TypeProperty)


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


class EmailAddress(Observable):
    _type = 'email-address'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'display_name': StringProperty(),
        'belongs_to_ref': ObjectReferenceProperty(),
    }


class EmailMIMEComponent(_STIXBase):
    _properties = {
        'body': StringProperty(),
        'body_raw_ref': ObjectReferenceProperty(),
        'content_type': StringProperty(),
        'content_disposition': StringProperty(),
    }


class EmailMessage(Observable):
    _type = 'email-message'
    _properties = {
        'type': TypeProperty(_type),
        'is_multipart': BooleanProperty(required=True),
        'date': TimestampProperty(),
        'content_type': StringProperty(),
        'from_ref': ObjectReferenceProperty(),
        'sender_ref': ObjectReferenceProperty(),
        'to_refs': ListProperty(ObjectReferenceProperty),
        'cc_refs': ListProperty(ObjectReferenceProperty),
        'bcc_refs': ListProperty(ObjectReferenceProperty),
        'subject': StringProperty(),
        'received_lines': ListProperty(StringProperty),
        'additional_header_fields': DictionaryProperty(),
        'body': StringProperty(),
        'body_multipart': ListProperty(EmbeddedObjectProperty(type=EmailMIMEComponent)),
        'raw_email_ref': ObjectReferenceProperty(),
    }


class File(Observable):
    _type = 'file'
    _properties = {
        'type': TypeProperty(_type),
    }
