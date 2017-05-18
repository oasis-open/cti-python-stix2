"""STIX 2.0 Cyber Observable Objects

Embedded observable object types, such as Email MIME Component, which is
embedded in Email Message objects, inherit from _STIXBase instead of Observable
and do not have a '_type' attribute.
"""

from .base import _Extension, _Observable, _STIXBase
from .exceptions import AtLeastOnePropertyError
from .properties import (BinaryProperty, BooleanProperty, DictionaryProperty,
                         EmbeddedObjectProperty, EnumProperty,
                         ExtensionsProperty, FloatProperty, HashesProperty,
                         HexProperty, IntegerProperty, ListProperty,
                         ObjectReferenceProperty, StringProperty,
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

    def _check_object_constraints(self):
        super(Artifact, self)._check_object_constraints()
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
        'contains_refs': ListProperty(ObjectReferenceProperty(valid_types=['file', 'directory'])),
    }


class DomainName(_Observable):
    _type = 'domain-name'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'resolves_to_refs': ListProperty(ObjectReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'domain-name'])),
    }


class EmailAddress(_Observable):
    _type = 'email-address'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'display_name': StringProperty(),
        'belongs_to_ref': ObjectReferenceProperty(valid_types='user-account'),
    }


class EmailMIMEComponent(_STIXBase):
    _properties = {
        'body': StringProperty(),
        'body_raw_ref': ObjectReferenceProperty(valid_types=['artifact', 'file']),
        'content_type': StringProperty(),
        'content_disposition': StringProperty(),
    }

    def _check_object_constraints(self):
        super(EmailMIMEComponent, self)._check_object_constraints()
        self._check_at_least_one_property(["body", "body_raw_ref"])


class EmailMessage(_Observable):
    _type = 'email-message'
    _properties = {
        'type': TypeProperty(_type),
        'is_multipart': BooleanProperty(required=True),
        'date': TimestampProperty(),
        'content_type': StringProperty(),
        'from_ref': ObjectReferenceProperty(valid_types='email-addr'),
        'sender_ref': ObjectReferenceProperty(valid_types='email-addr'),
        'to_refs': ListProperty(ObjectReferenceProperty(valid_types='email-addr')),
        'cc_refs': ListProperty(ObjectReferenceProperty(valid_types='email-addr')),
        'bcc_refs': ListProperty(ObjectReferenceProperty(valid_types='email-addr')),
        'subject': StringProperty(),
        'received_lines': ListProperty(StringProperty),
        'additional_header_fields': DictionaryProperty(),
        'body': StringProperty(),
        'body_multipart': ListProperty(EmbeddedObjectProperty(type=EmailMIMEComponent)),
        'raw_email_ref': ObjectReferenceProperty(valid_types='artifact'),
    }

    def _check_object_constraints(self):
        super(EmailMessage, self)._check_object_constraints()
        self._check_properties_dependency(["is_multipart"], ["body_multipart"])
        # self._dependency(["is_multipart"], ["body"], [False])


class ArchiveExt(_Extension):
    _properties = {
        'contains_refs': ListProperty(ObjectReferenceProperty(valid_types='file'), required=True),
        'version': StringProperty(),
        'comment': StringProperty(),
    }


class AlternateDataStream(_STIXBase):
    _properties = {
        'name': StringProperty(required=True),
        'hashes': HashesProperty(),
        'size': IntegerProperty(),
    }


class NTFSExt(_Extension):
    _properties = {
        'sid': StringProperty(),
        'alternate_data_streams': ListProperty(EmbeddedObjectProperty(type=AlternateDataStream)),
    }


class PDFExt(_Extension):
    _properties = {
        'version': StringProperty(),
        'is_optimized': BooleanProperty(),
        'document_info_dict': DictionaryProperty(),
        'pdfid0': StringProperty(),
        'pdfid1': StringProperty(),
    }


class RasterImageExt(_Extension):
    _properties = {
        'image_height': IntegerProperty(),
        'image_weight': IntegerProperty(),
        'bits_per_pixel': IntegerProperty(),
        'image_compression_algorithm': StringProperty(),
        'exif_tags': DictionaryProperty(),
    }


class WindowsPEOptionalHeaderType(_STIXBase):
    _properties = {
        'magic_hex': HexProperty(),
        'major_linker_version': IntegerProperty(),
        'minor_linker_version': IntegerProperty(),
        'size_of_code': IntegerProperty(),
        'size_of_initialized_data': IntegerProperty(),
        'size_of_uninitialized_data': IntegerProperty(),
        'address_of_entry_point': IntegerProperty(),
        'base_of_code': IntegerProperty(),
        'base_of_data': IntegerProperty(),
        'image_base': IntegerProperty(),
        'section_alignment': IntegerProperty(),
        'file_alignment': IntegerProperty(),
        'major_os_version': IntegerProperty(),
        'minor_os_version': IntegerProperty(),
        'major_image_version': IntegerProperty(),
        'minor_image_version': IntegerProperty(),
        'major_subsystem_version': IntegerProperty(),
        'minor_subsystem_version': IntegerProperty(),
        'win32_version_value_hex': HexProperty(),
        'size_of_image': IntegerProperty(),
        'size_of_headers': IntegerProperty(),
        'checksum_hex': HexProperty(),
        'subsystem_hex': HexProperty(),
        'dll_characteristics_hex': HexProperty(),
        'size_of_stack_reserve': IntegerProperty(),
        'size_of_stack_commit': IntegerProperty(),
        'size_of_heap_reserve': IntegerProperty(),
        'size_of_heap_commit': IntegerProperty(),
        'loader_flags_hex': HexProperty(),
        'number_of_rva_and_sizes': IntegerProperty(),
        'hashes': HashesProperty(),
    }

    def _check_object_constraints(self):
        super(WindowsPEOptionalHeaderType, self)._check_object_constraints()
        self._check_at_least_one_property()


class WindowsPESection(_STIXBase):
    _properties = {
        'name': StringProperty(required=True),
        'size': IntegerProperty(),
        'entropy': FloatProperty(),
        'hashes': HashesProperty(),
    }


class WindowsPEBinaryExt(_Extension):
    _properties = {
        'pe_type': StringProperty(required=True),  # open_vocab
        'imphash': StringProperty(),
        'machine_hex': HexProperty(),
        'number_of_sections': IntegerProperty(),
        'time_date_stamp': TimestampProperty(),
        'pointer_to_symbol_table_hex': HexProperty(),
        'number_of_symbols': IntegerProperty(),
        'size_of_optional_header': IntegerProperty(),
        'characteristics_hex': HexProperty(),
        'file_header_hashes': HashesProperty(),
        'optional_header': EmbeddedObjectProperty(type=WindowsPEOptionalHeaderType),
        'sections': ListProperty(EmbeddedObjectProperty(type=WindowsPESection)),
    }


class File(_Observable):
    _type = 'file'
    _properties = {
        'type': TypeProperty(_type),
        'extensions': ExtensionsProperty(enclosing_type=_type),
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
        'parent_directory_ref': ObjectReferenceProperty(valid_types='directory'),
        'is_encrypted': BooleanProperty(),
        'encryption_algorithm': StringProperty(),
        'decryption_key': StringProperty(),
        'contains_refs': ListProperty(ObjectReferenceProperty),
        'content_ref': ObjectReferenceProperty(valid_types='artifact'),
    }

    def _check_object_constraints(self):
        super(File, self)._check_object_constraints()
        self._check_properties_dependency(["is_encrypted"], ["encryption_algorithm", "decryption_key"])
        self._check_at_least_one_property(["hashes", "name"])


class IPv4Address(_Observable):
    _type = 'ipv4-addr'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'resolves_to_refs': ListProperty(ObjectReferenceProperty(valid_types='mac-addr')),
        'belongs_to_refs': ListProperty(ObjectReferenceProperty(valid_types='autonomous-system')),
    }


class IPv6Address(_Observable):
    _type = 'ipv6-addr'
    _properties = {
        'type': TypeProperty(_type),
        'value': StringProperty(required=True),
        'resolves_to_refs': ListProperty(ObjectReferenceProperty(valid_types='mac-addr')),
        'belongs_to_refs': ListProperty(ObjectReferenceProperty(valid_types='autonomous-system')),
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


class HTTPRequestExt(_Extension):
    _properties = {
        'request_method': StringProperty(required=True),
        'request_value': StringProperty(required=True),
        'request_version': StringProperty(),
        'request_header': DictionaryProperty(),
        'message_body_length': IntegerProperty(),
        'message_body_data_ref': ObjectReferenceProperty(valid_types='artifact'),
    }


class ICMPExt(_Extension):
    _properties = {
        'icmp_type_hex': HexProperty(required=True),
        'icmp_code_hex': HexProperty(required=True),
    }


class SocketExt(_Extension):
    _properties = {
        'address_family': EnumProperty([
            "AF_UNSPEC",
            "AF_INET",
            "AF_IPX",
            "AF_APPLETALK",
            "AF_NETBIOS",
            "AF_INET6",
            "AF_IRDA",
            "AF_BTH",
        ], required=True),
        'is_blocking': BooleanProperty(),
        'is_listening': BooleanProperty(),
        'protocol_family': EnumProperty([
            "PF_INET",
            "PF_IPX",
            "PF_APPLETALK",
            "PF_INET6",
            "PF_AX25",
            "PF_NETROM"
        ]),
        'options': DictionaryProperty(),
        'socket_type': EnumProperty([
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "SOCK_RDM",
            "SOCK_SEQPACKET",
        ]),
    }


class TCPExt(_Extension):
    _properties = {
        'src_flags_hex': HexProperty(),
        'dst_flags_hex': HexProperty(),
    }


class NetworkTraffic(_Observable):
    _type = 'network-traffic'
    _properties = {
        'type': TypeProperty(_type),
        'extensions': ExtensionsProperty(enclosing_type=_type),
        'start': TimestampProperty(),
        'end': TimestampProperty(),
        'is_active': BooleanProperty(),
        'src_ref': ObjectReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name']),
        'dst_ref': ObjectReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name']),
        'src_port': IntegerProperty(),
        'dst_port': IntegerProperty(),
        'protocols': ListProperty(StringProperty, required=True),
        'src_byte_count': IntegerProperty(),
        'dst_byte_count': IntegerProperty(),
        'src_packets': IntegerProperty(),
        'dst_packets': IntegerProperty(),
        'ipfix': DictionaryProperty(),
        'src_payload_ref': ObjectReferenceProperty(valid_types='artifact'),
        'dst_payload_ref': ObjectReferenceProperty(valid_types='artifact'),
        'encapsulates_refs': ListProperty(ObjectReferenceProperty(valid_types='network-traffic')),
        'encapsulates_by_ref': ObjectReferenceProperty(valid_types='network-traffic'),
    }

    def _check_object_constraints(self):
        super(NetworkTraffic, self)._check_object_constraints()
        self._check_at_least_one_property(["src_ref", "dst_ref"])


class WindowsProcessExt(_Extension):
    _properties = {
        'aslr_enabled': BooleanProperty(),
        'dep_enabled': BooleanProperty(),
        'priority': StringProperty(),
        'owner_sid': StringProperty(),
        'window_title': StringProperty(),
        'startup_info': DictionaryProperty(),
    }


class WindowsServiceExt(_Extension):
    _properties = {
        'service_name': StringProperty(required=True),
        'descriptions': ListProperty(StringProperty),
        'display_name': StringProperty(),
        'group_name': StringProperty(),
        'start_type': EnumProperty([
            "SERVICE_AUTO_START",
            "SERVICE_BOOT_START",
            "SERVICE_DEMAND_START",
            "SERVICE_DISABLED",
            "SERVICE_SYSTEM_ALERT",
        ]),
        'service_dll_refs': ListProperty(ObjectReferenceProperty(valid_types='file')),
        'service_type': EnumProperty([
            "SERVICE_KERNEL_DRIVER",
            "SERVICE_FILE_SYSTEM_DRIVER",
            "SERVICE_WIN32_OWN_PROCESS",
            "SERVICE_WIN32_SHARE_PROCESS",
        ]),
        'service_status': EnumProperty([
            "SERVICE_CONTINUE_PENDING",
            "SERVICE_PAUSE_PENDING",
            "SERVICE_PAUSED",
            "SERVICE_RUNNING",
            "SERVICE_START_PENDING",
            "SERVICE_STOP_PENDING",
            "SERVICE_STOPPED",
        ]),
    }


class Process(_Observable):
    _type = 'process'
    _properties = {
        'type': TypeProperty(_type),
        'extensions': ExtensionsProperty(enclosing_type=_type),
        'is_hidden': BooleanProperty(),
        'pid': IntegerProperty(),
        'name': StringProperty(),
        # this is not the created timestamps of the object itself
        'created': TimestampProperty(),
        'cwd': StringProperty(),
        'arguments': ListProperty(StringProperty),
        'command_line': StringProperty(),
        'environment_variables': DictionaryProperty(),
        'opened_connection_refs': ListProperty(ObjectReferenceProperty(valid_types='network-traffic')),
        'creator_user_ref': ObjectReferenceProperty(valid_types='user-account'),
        'binary_ref': ObjectReferenceProperty(valid_types='file'),
        'parent_ref': ObjectReferenceProperty(valid_types='process'),
        'child_refs': ListProperty(ObjectReferenceProperty('process')),
    }

    def _check_object_constraints(self):
        # no need to check windows-service-ext, since it has a required property
        super(Process, self)._check_object_constraints()
        try:
            self._check_at_least_one_property()
            if self.extensions and "windows-process-ext" in self.extensions:
                self.extensions["windows-process-ext"]._check_at_least_one_property()
        except AtLeastOnePropertyError as enclosing_exc:
            if not self.extensions:
                raise enclosing_exc
            else:
                if "windows-process-ext" in self.extensions:
                    self.extensions["windows-process-ext"]._check_at_least_one_property()


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


class UNIXAccountExt(_Extension):
    _properties = {
        'gid': IntegerProperty(),
        'groups': ListProperty(StringProperty),
        'home_dir': StringProperty(),
        'shell': StringProperty(),
    }


class UserAccount(_Observable):
    _type = 'user-account'
    _properties = {
        'type': TypeProperty(_type),
        'extensions': ExtensionsProperty(enclosing_type=_type),
        'user_id': StringProperty(required=True),
        'account_login': StringProperty(),
        'account_type': StringProperty(),   # open vocab
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
        'creator_user_ref': ObjectReferenceProperty(valid_types='user-account'),
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
