"""STIX 2.0 Cyber Observable Objects

Embedded observable object types, such as Email MIME Component, which is
embedded in Email Message objects, inherit from _STIXBase instead of Observable
and do not have a '_type' attribute.
"""

from .base import _Observable, _STIXBase
from .properties import (BinaryProperty, BooleanProperty, DictionaryProperty,
                         EmbeddedObjectProperty, EnumProperty, HashesProperty,
                         HexProperty, IntegerProperty, ListProperty,
                         ObjectReferenceProperty, Property, StringProperty,
                         TimestampProperty, TypeProperty)


class Artifact(_Observable):
    _type = 'artifact'
    _properties = {
        'type': TypeProperty(_type),
        'mime_type': StringProperty(),
        'payload_bin': BinaryProperty(),
        'url': StringProperty(),
        'hashes': HashesProperty(),
    }

    def _check_object_constaints(self):
        super(Artifact, self)._check_object_constaints()
        self._check_mutually_exclusive_properties(["payload_bin", "url"])
        self._check_properties_dependency(["hashes"], ["url"])


class AutonomousSystem(_Observable):
    _type = 'autonomous-system'
    _properties = {
        'type': TypeProperty(_type),
        'number': IntegerProperty(),
        'name': StringProperty(),
        'rir': StringProperty(),
    }


class Directory(_Observable):
    _type = 'directory'
    _properties = {
        'type': TypeProperty(_type),
        'path': StringProperty(required=True),
        'path_enc': StringProperty(),
        # these are not the created/modified timestamps of the object itself
        'created': TimestampProperty(),
        'modified': TimestampProperty(),
        'accessed': TimestampProperty(),
        'contains_refs': ListProperty(ObjectReferenceProperty),
    }


class DomainName(_Observable):
    _type = 'domain-name'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'resolves_to_refs': ListProperty(ObjectReferenceProperty),
    }


class EmailAddress(_Observable):
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

    def _check_object_constaints(self):
        super(EmailMIMEComponent, self)._check_object_constaints()
        self._check_at_least_one_property(["body", "body_raw_ref"])


class EmailMessage(_Observable):
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

    def _check_object_constaints(self):
        super(EmailMessage, self)._check_object_constaints()
        self._check_properties_dependency(["is_multipart"], ["body_multipart"])
        # self._dependency(["is_multipart"], ["body"], [False])


class File(_Observable):
    _type = 'file'
    _properties = {
        'type': TypeProperty(_type),
        # extensions
        'hashes': HashesProperty(),
        'size': IntegerProperty(),
        'name': StringProperty(),
        'name_enc': StringProperty(),
        'magic_number_hex': HexProperty(),
        'mime_type': StringProperty(),
        # these are not the created/modified timestamps of the object itself
        'created': TimestampProperty(),
        'modified': TimestampProperty(),
        'accessed': TimestampProperty(),
        'parent_directory_ref': ObjectReferenceProperty(),
        'is_encrypted': BooleanProperty(),
        'encryption_algorithm': StringProperty(),
        'decryption_key': StringProperty(),
        'contains_refs': ListProperty(ObjectReferenceProperty),
        'content_ref': ObjectReferenceProperty(),
    }

    def _check_object_constaints(self):
        super(File, self)._check_object_constaints()
        self._check_properties_dependency(["is_encrypted"], ["encryption_algorithm", "decryption_key"])
        self._check_at_least_one_property(["hashes", "name"])


class IPv4Address(_Observable):
    _type = 'ipv4-addr'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'resolves_to_refs': ListProperty(ObjectReferenceProperty),
        'belongs_to_refs': ListProperty(ObjectReferenceProperty),
    }


class IPv6Address(_Observable):
    _type = 'ipv6-addr'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'resolves_to_refs': ListProperty(ObjectReferenceProperty),
        'belongs_to_refs': ListProperty(ObjectReferenceProperty),
    }


class MACAddress(_Observable):
    _type = 'mac-addr'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
    }


class Mutex(_Observable):
    _type = 'mutex'
    _properties = {
        'type': TypeProperty(_type),
        'name': StringProperty(),
    }


class NetworkTraffic(_Observable):
    _type = 'network-traffic'
    _properties = {
        'type': TypeProperty(_type),
        # extensions
        'start': TimestampProperty(),
        'end': TimestampProperty(),
        'is_active': BooleanProperty(),
        'src_ref': ObjectReferenceProperty(),
        'dst_ref': ObjectReferenceProperty(),
        'src_port': IntegerProperty(),
        'dst_port': IntegerProperty(),
        'protocols': ListProperty(StringProperty, required=True),
        'src_byte_count': IntegerProperty(),
        'dst_byte_count': IntegerProperty(),
        'src_packets': IntegerProperty(),
        'dst_packets': IntegerProperty(),
        'ipfix': DictionaryProperty(),
        'src_payload_ref': ObjectReferenceProperty(),
        'dst_payload_ref': ObjectReferenceProperty(),
        'encapsulates_refs': ListProperty(ObjectReferenceProperty),
        'encapsulates_by_ref': ObjectReferenceProperty(),
    }

    def _check_object_constaints(self):
        super(NetworkTraffic, self)._check_object_constaints()
        self._check_at_least_one_property(["src_ref", "dst_ref"])


class Process(_Observable):
    _type = 'process'
    _properties = {
        'type': TypeProperty(_type),
        # extensions
        'is_hidden': BooleanProperty(),
        'pid': IntegerProperty(),
        'name': StringProperty(),
        # this is not the created timestamps of the object itself
        'created': TimestampProperty(),
        'cwd': StringProperty(),
        'arguments': ListProperty(StringProperty),
        'command_line': StringProperty(),
        'environment_variables': DictionaryProperty(),
        'opened_connection_refs': ListProperty(ObjectReferenceProperty),
        'creator_user_ref': ObjectReferenceProperty(),
        'binary_ref': ObjectReferenceProperty(),
        'parent_ref': ObjectReferenceProperty(),
        'child_refs': ListProperty(ObjectReferenceProperty),
    }


class Software(_Observable):
    _type = 'software'
    _properties = {
        'type': TypeProperty(_type),
        'name': StringProperty(required=True),
        'cpe': StringProperty(),
        'languages': ListProperty(StringProperty),
        'vendor': StringProperty(),
        'version': StringProperty(),
    }


class URL(_Observable):
    _type = 'url'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
    }


class UserAccount(_Observable):
    _type = 'user-account'
    _properties = {
        'type': TypeProperty(_type),
        # extensions
        'user_id': StringProperty(required=True),
        'account_login': StringProperty(),
        'account_type': StringProperty(),
        'display_name': StringProperty(),
        'is_service_account': BooleanProperty(),
        'is_privileged': BooleanProperty(),
        'can_escalate_privs': BooleanProperty(),
        'is_disabled': BooleanProperty(),
        'account_created': TimestampProperty(),
        'account_expires': TimestampProperty(),
        'password_last_changed': TimestampProperty(),
        'account_first_login': TimestampProperty(),
        'account_last_login': TimestampProperty(),
    }


class WindowsRegistryValueType(_STIXBase):
    _type = 'windows-registry-value-type'
    _properties = {
        'name': StringProperty(required=True),
        'data': StringProperty(),
        'data_type': EnumProperty([
            'REG_NONE',
            'REG_SZ',
            'REG_EXPAND_SZ',
            'REG_BINARY',
            'REG_DWORD',
            'REG_DWORD_BIG_ENDIAN',
            'REG_LINK',
            'REG_MULTI_SZ',
            'REG_RESOURCE_LIST',
            'REG_FULL_RESOURCE_DESCRIPTION',
            'REG_RESOURCE_REQUIREMENTS_LIST',
            'REG_QWORD',
            'REG_INVALID_TYPE',
        ]),
    }


class WindowsRegistryKey(_Observable):
    _type = 'windows-registry-key'
    _properties = {
        'type': TypeProperty(_type),
        'key': StringProperty(required=True),
        'values': ListProperty(EmbeddedObjectProperty(type=WindowsRegistryValueType)),
        # this is not the modified timestamps of the object itself
        'modified': TimestampProperty(),
        'creator_user_ref': ObjectReferenceProperty(),
        'number_of_subkeys': IntegerProperty(),
    }

    @property
    def values(self):
      # Needed because 'values' is a property on collections.Mapping objects
        return self._inner['values']
      

class X509V3ExtenstionsType(_STIXBase):
    _type = 'x509-v3-extensions-type'
    _properties = {
        'basic_constraints': StringProperty(),
        'name_constraints': StringProperty(),
        'policy_constraints': StringProperty(),
        'key_usage': StringProperty(),
        'extended_key_usage': StringProperty(),
        'subject_key_identifier': StringProperty(),
        'authority_key_identifier': StringProperty(),
        'subject_alternative_name': StringProperty(),
        'issuer_alternative_name': StringProperty(),
        'subject_directory_attributes': StringProperty(),
        'crl_distribution_points': StringProperty(),
        'inhibit_any_policy': StringProperty(),
        'private_key_usage_period_not_before': TimestampProperty(),
        'private_key_usage_period_not_after': TimestampProperty(),
        'certificate_policies': StringProperty(),
        'policy_mappings': StringProperty(),
    }
    

class X509Certificate(_Observable):
    _type = 'x509-certificate'
    _properties = {
        'type': TypeProperty(_type),
        'is_self_signed': BooleanProperty(),
        'hashes': HashesProperty(),
        'version': StringProperty(),
        'serial_number': StringProperty(),
        'signature_algorithm': StringProperty(),
        'issuer': StringProperty(),
        'validity_not_before': TimestampProperty(),
        'validity_not_after': TimestampProperty(),
        'subject': StringProperty(),
        'subject_public_key_algorithm': StringProperty(),
        'subject_public_key_modulus': StringProperty(),
        'subject_public_key_exponent': IntegerProperty(),
        'x509_v3_extensions': EmbeddedObjectProperty(type=X509V3ExtenstionsType),
    }
