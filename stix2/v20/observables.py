"""STIX 2.0 Cyber Observable Objects.

Embedded observable object types, such as Email MIME Component, which is
embedded in Email Message objects, inherit from ``_STIXBase`` instead of
Observable and do not have a ``_type`` attribute.
"""

from collections import OrderedDict

from ..base import _Extension, _Observable, _STIXBase
from ..exceptions import (AtLeastOnePropertyError, DependentPropertiesError,
                          ParseError)
from ..properties import (BinaryProperty, BooleanProperty, DictionaryProperty,
                          EmbeddedObjectProperty, EnumProperty, FloatProperty,
                          HashesProperty, HexProperty, IntegerProperty,
                          ListProperty, ObjectReferenceProperty, Property,
                          StringProperty, TimestampProperty, TypeProperty)
from ..utils import get_dict


class ObservableProperty(Property):
    """Property for holding Cyber Observable Objects.
    """

    def clean(self, value):
        try:
            dictified = get_dict(value)
        except ValueError:
            raise ValueError("The observable property must contain a dictionary")
        if dictified == {}:
            raise ValueError("The observable property must contain a non-empty dictionary")

        valid_refs = dict((k, v['type']) for (k, v) in dictified.items())

        for key, obj in dictified.items():
            parsed_obj = parse_observable(obj, valid_refs)
            dictified[key] = parsed_obj

        return dictified


class ExtensionsProperty(DictionaryProperty):
    """Property for representing extensions on Observable objects.
    """

    def __init__(self, enclosing_type=None, required=False):
        self.enclosing_type = enclosing_type
        super(ExtensionsProperty, self).__init__(required)

    def clean(self, value):
        try:
            dictified = get_dict(value)
        except ValueError:
            raise ValueError("The extensions property must contain a dictionary")
        if dictified == {}:
            raise ValueError("The extensions property must contain a non-empty dictionary")

        if self.enclosing_type in EXT_MAP:
            specific_type_map = EXT_MAP[self.enclosing_type]
            for key, subvalue in dictified.items():
                if key in specific_type_map:
                    cls = specific_type_map[key]
                    if type(subvalue) is dict:
                        dictified[key] = cls(**subvalue)
                    elif type(subvalue) is cls:
                        dictified[key] = subvalue
                    else:
                        raise ValueError("Cannot determine extension type.")
                else:
                    raise ValueError("The key used in the extensions dictionary is not an extension type name")
        else:
            raise ValueError("The enclosing type '%s' has no extensions defined" % self.enclosing_type)
        return dictified


class Artifact(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716219>`__.
    """  # noqa

    _type = 'artifact'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('mime_type', StringProperty()),
        ('payload_bin', BinaryProperty()),
        ('url', StringProperty()),
        ('hashes', HashesProperty()),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])

    def _check_object_constraints(self):
        super(Artifact, self)._check_object_constraints()
        self._check_mutually_exclusive_properties(["payload_bin", "url"])
        self._check_properties_dependency(["hashes"], ["url"])


class AutonomousSystem(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716221>`__.
    """  # noqa

    _type = 'autonomous-system'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('number', IntegerProperty(required=True)),
        ('name', StringProperty()),
        ('rir', StringProperty()),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class Directory(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716223>`__.
    """  # noqa

    _type = 'directory'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('path', StringProperty(required=True)),
        ('path_enc', StringProperty()),
        # these are not the created/modified timestamps of the object itself
        ('created', TimestampProperty()),
        ('modified', TimestampProperty()),
        ('accessed', TimestampProperty()),
        ('contains_refs', ListProperty(ObjectReferenceProperty(valid_types=['file', 'directory']))),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class DomainName(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716225>`__.
    """  # noqa

    _type = 'domain-name'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('value', StringProperty(required=True)),
        ('resolves_to_refs', ListProperty(ObjectReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'domain-name']))),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class EmailAddress(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716227>`__.
    """  # noqa

    _type = 'email-addr'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('value', StringProperty(required=True)),
        ('display_name', StringProperty()),
        ('belongs_to_ref', ObjectReferenceProperty(valid_types='user-account')),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class EmailMIMEComponent(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716231>`__.
    """  # noqa

    _properties = OrderedDict()
    _properties.update([
        ('body', StringProperty()),
        ('body_raw_ref', ObjectReferenceProperty(valid_types=['artifact', 'file'])),
        ('content_type', StringProperty()),
        ('content_disposition', StringProperty()),
    ])

    def _check_object_constraints(self):
        super(EmailMIMEComponent, self)._check_object_constraints()
        self._check_at_least_one_property(["body", "body_raw_ref"])


class EmailMessage(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716229>`__.
    """  # noqa

    _type = 'email-message'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('is_multipart', BooleanProperty(required=True)),
        ('date', TimestampProperty()),
        ('content_type', StringProperty()),
        ('from_ref', ObjectReferenceProperty(valid_types='email-addr')),
        ('sender_ref', ObjectReferenceProperty(valid_types='email-addr')),
        ('to_refs', ListProperty(ObjectReferenceProperty(valid_types='email-addr'))),
        ('cc_refs', ListProperty(ObjectReferenceProperty(valid_types='email-addr'))),
        ('bcc_refs', ListProperty(ObjectReferenceProperty(valid_types='email-addr'))),
        ('subject', StringProperty()),
        ('received_lines', ListProperty(StringProperty)),
        ('additional_header_fields', DictionaryProperty()),
        ('body', StringProperty()),
        ('body_multipart', ListProperty(EmbeddedObjectProperty(type=EmailMIMEComponent))),
        ('raw_email_ref', ObjectReferenceProperty(valid_types='artifact')),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])

    def _check_object_constraints(self):
        super(EmailMessage, self)._check_object_constraints()
        self._check_properties_dependency(["is_multipart"], ["body_multipart"])
        if self.get("is_multipart") is True and self.get("body"):
            # 'body' MAY only be used if is_multipart is false.
            raise DependentPropertiesError(self.__class__, [("is_multipart", "body")])


class ArchiveExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716235>`__.
    """  # noqa

    _type = 'archive-ext'
    _properties = OrderedDict()
    _properties.update([
        ('contains_refs', ListProperty(ObjectReferenceProperty(valid_types='file'), required=True)),
        ('version', StringProperty()),
        ('comment', StringProperty()),
    ])


class AlternateDataStream(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716239>`__.
    """  # noqa

    _properties = OrderedDict()
    _properties.update([
        ('name', StringProperty(required=True)),
        ('hashes', HashesProperty()),
        ('size', IntegerProperty()),
    ])


class NTFSExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716237>`__.
    """  # noqa

    _type = 'ntfs-ext'
    _properties = OrderedDict()
    _properties.update([
        ('sid', StringProperty()),
        ('alternate_data_streams', ListProperty(EmbeddedObjectProperty(type=AlternateDataStream))),
    ])


class PDFExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716241>`__.
    """  # noqa

    _type = 'pdf-ext'
    _properties = OrderedDict()
    _properties.update([
        ('version', StringProperty()),
        ('is_optimized', BooleanProperty()),
        ('document_info_dict', DictionaryProperty()),
        ('pdfid0', StringProperty()),
        ('pdfid1', StringProperty()),
    ])


class RasterImageExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716243>`__.
    """  # noqa

    _type = 'raster-image-ext'
    _properties = OrderedDict()
    _properties.update([
        ('image_height', IntegerProperty()),
        ('image_weight', IntegerProperty()),
        ('bits_per_pixel', IntegerProperty()),
        ('image_compression_algorithm', StringProperty()),
        ('exif_tags', DictionaryProperty()),
    ])


class WindowsPEOptionalHeaderType(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716248>`__.
    """  # noqa

    _properties = OrderedDict()
    _properties.update([
        ('magic_hex', HexProperty()),
        ('major_linker_version', IntegerProperty()),
        ('minor_linker_version', IntegerProperty()),
        ('size_of_code', IntegerProperty()),
        ('size_of_initialized_data', IntegerProperty()),
        ('size_of_uninitialized_data', IntegerProperty()),
        ('address_of_entry_point', IntegerProperty()),
        ('base_of_code', IntegerProperty()),
        ('base_of_data', IntegerProperty()),
        ('image_base', IntegerProperty()),
        ('section_alignment', IntegerProperty()),
        ('file_alignment', IntegerProperty()),
        ('major_os_version', IntegerProperty()),
        ('minor_os_version', IntegerProperty()),
        ('major_image_version', IntegerProperty()),
        ('minor_image_version', IntegerProperty()),
        ('major_subsystem_version', IntegerProperty()),
        ('minor_subsystem_version', IntegerProperty()),
        ('win32_version_value_hex', HexProperty()),
        ('size_of_image', IntegerProperty()),
        ('size_of_headers', IntegerProperty()),
        ('checksum_hex', HexProperty()),
        ('subsystem_hex', HexProperty()),
        ('dll_characteristics_hex', HexProperty()),
        ('size_of_stack_reserve', IntegerProperty()),
        ('size_of_stack_commit', IntegerProperty()),
        ('size_of_heap_reserve', IntegerProperty()),
        ('size_of_heap_commit', IntegerProperty()),
        ('loader_flags_hex', HexProperty()),
        ('number_of_rva_and_sizes', IntegerProperty()),
        ('hashes', HashesProperty()),
    ])

    def _check_object_constraints(self):
        super(WindowsPEOptionalHeaderType, self)._check_object_constraints()
        self._check_at_least_one_property()


class WindowsPESection(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716250>`__.
    """  # noqa

    _properties = OrderedDict()
    _properties.update([
        ('name', StringProperty(required=True)),
        ('size', IntegerProperty()),
        ('entropy', FloatProperty()),
        ('hashes', HashesProperty()),
    ])


class WindowsPEBinaryExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716245>`__.
    """  # noqa

    _type = 'windows-pebinary-ext'
    _properties = OrderedDict()
    _properties.update([
        ('pe_type', StringProperty(required=True)),  # open_vocab
        ('imphash', StringProperty()),
        ('machine_hex', HexProperty()),
        ('number_of_sections', IntegerProperty()),
        ('time_date_stamp', TimestampProperty(precision='second')),
        ('pointer_to_symbol_table_hex', HexProperty()),
        ('number_of_symbols', IntegerProperty()),
        ('size_of_optional_header', IntegerProperty()),
        ('characteristics_hex', HexProperty()),
        ('file_header_hashes', HashesProperty()),
        ('optional_header', EmbeddedObjectProperty(type=WindowsPEOptionalHeaderType)),
        ('sections', ListProperty(EmbeddedObjectProperty(type=WindowsPESection))),
    ])


class File(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716233>`__.
    """  # noqa

    _type = 'file'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('hashes', HashesProperty()),
        ('size', IntegerProperty()),
        ('name', StringProperty()),
        ('name_enc', StringProperty()),
        ('magic_number_hex', HexProperty()),
        ('mime_type', StringProperty()),
        # these are not the created/modified timestamps of the object itself
        ('created', TimestampProperty()),
        ('modified', TimestampProperty()),
        ('accessed', TimestampProperty()),
        ('parent_directory_ref', ObjectReferenceProperty(valid_types='directory')),
        ('is_encrypted', BooleanProperty()),
        ('encryption_algorithm', StringProperty()),
        ('decryption_key', StringProperty()),
        ('contains_refs', ListProperty(ObjectReferenceProperty)),
        ('content_ref', ObjectReferenceProperty(valid_types='artifact')),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])

    def _check_object_constraints(self):
        super(File, self)._check_object_constraints()
        self._check_properties_dependency(["is_encrypted"], ["encryption_algorithm", "decryption_key"])
        self._check_at_least_one_property(["hashes", "name"])


class IPv4Address(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716252>`__.
    """  # noqa

    _type = 'ipv4-addr'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('value', StringProperty(required=True)),
        ('resolves_to_refs', ListProperty(ObjectReferenceProperty(valid_types='mac-addr'))),
        ('belongs_to_refs', ListProperty(ObjectReferenceProperty(valid_types='autonomous-system'))),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class IPv6Address(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716254>`__.
    """  # noqa

    _type = 'ipv6-addr'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('value', StringProperty(required=True)),
        ('resolves_to_refs', ListProperty(ObjectReferenceProperty(valid_types='mac-addr'))),
        ('belongs_to_refs', ListProperty(ObjectReferenceProperty(valid_types='autonomous-system'))),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class MACAddress(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716256>`__.
    """  # noqa

    _type = 'mac-addr'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('value', StringProperty(required=True)),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class Mutex(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716258>`__.
    """  # noqa

    _type = 'mutex'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('name', StringProperty(required=True)),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class HTTPRequestExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716262>`__.
    """  # noqa

    _type = 'http-request-ext'
    _properties = OrderedDict()
    _properties.update([
        ('request_method', StringProperty(required=True)),
        ('request_value', StringProperty(required=True)),
        ('request_version', StringProperty()),
        ('request_header', DictionaryProperty()),
        ('message_body_length', IntegerProperty()),
        ('message_body_data_ref', ObjectReferenceProperty(valid_types='artifact')),
    ])


class ICMPExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716264>`__.
    """  # noqa

    _type = 'icmp-ext'
    _properties = OrderedDict()
    _properties.update([
        ('icmp_type_hex', HexProperty(required=True)),
        ('icmp_code_hex', HexProperty(required=True)),
    ])


class SocketExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716266>`__.
    """  # noqa

    _type = 'socket-ext'
    _properties = OrderedDict()
    _properties.update([
        ('address_family', EnumProperty(allowed=[
            "AF_UNSPEC",
            "AF_INET",
            "AF_IPX",
            "AF_APPLETALK",
            "AF_NETBIOS",
            "AF_INET6",
            "AF_IRDA",
            "AF_BTH",
        ], required=True)),
        ('is_blocking', BooleanProperty()),
        ('is_listening', BooleanProperty()),
        ('protocol_family', EnumProperty(allowed=[
            "PF_INET",
            "PF_IPX",
            "PF_APPLETALK",
            "PF_INET6",
            "PF_AX25",
            "PF_NETROM"
        ])),
        ('options', DictionaryProperty()),
        ('socket_type', EnumProperty(allowed=[
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "SOCK_RDM",
            "SOCK_SEQPACKET",
        ])),
        ('socket_descriptor', IntegerProperty()),
        ('socket_handle', IntegerProperty()),
    ])


class TCPExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716271>`__.
    """  # noqa

    _type = 'tcp-ext'
    _properties = OrderedDict()
    _properties.update([
        ('src_flags_hex', HexProperty()),
        ('dst_flags_hex', HexProperty()),
    ])


class NetworkTraffic(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716260>`__.
    """  # noqa

    _type = 'network-traffic'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('start', TimestampProperty()),
        ('end', TimestampProperty()),
        ('is_active', BooleanProperty()),
        ('src_ref', ObjectReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'])),
        ('dst_ref', ObjectReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'])),
        ('src_port', IntegerProperty()),
        ('dst_port', IntegerProperty()),
        ('protocols', ListProperty(StringProperty, required=True)),
        ('src_byte_count', IntegerProperty()),
        ('dst_byte_count', IntegerProperty()),
        ('src_packets', IntegerProperty()),
        ('dst_packets', IntegerProperty()),
        ('ipfix', DictionaryProperty()),
        ('src_payload_ref', ObjectReferenceProperty(valid_types='artifact')),
        ('dst_payload_ref', ObjectReferenceProperty(valid_types='artifact')),
        ('encapsulates_refs', ListProperty(ObjectReferenceProperty(valid_types='network-traffic'))),
        ('encapsulates_by_ref', ObjectReferenceProperty(valid_types='network-traffic')),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])

    def _check_object_constraints(self):
        super(NetworkTraffic, self)._check_object_constraints()
        self._check_at_least_one_property(["src_ref", "dst_ref"])


class WindowsProcessExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716275>`__.
    """  # noqa

    _type = 'windows-process-ext'
    _properties = OrderedDict()
    _properties.update([
        ('aslr_enabled', BooleanProperty()),
        ('dep_enabled', BooleanProperty()),
        ('priority', StringProperty()),
        ('owner_sid', StringProperty()),
        ('window_title', StringProperty()),
        ('startup_info', DictionaryProperty()),
    ])


class WindowsServiceExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716277>`__.
    """  # noqa

    _type = 'windows-service-ext'
    _properties = OrderedDict()
    _properties.update([
        ('service_name', StringProperty(required=True)),
        ('descriptions', ListProperty(StringProperty)),
        ('display_name', StringProperty()),
        ('group_name', StringProperty()),
        ('start_type', EnumProperty(allowed=[
            "SERVICE_AUTO_START",
            "SERVICE_BOOT_START",
            "SERVICE_DEMAND_START",
            "SERVICE_DISABLED",
            "SERVICE_SYSTEM_ALERT",
        ])),
        ('service_dll_refs', ListProperty(ObjectReferenceProperty(valid_types='file'))),
        ('service_type', EnumProperty(allowed=[
            "SERVICE_KERNEL_DRIVER",
            "SERVICE_FILE_SYSTEM_DRIVER",
            "SERVICE_WIN32_OWN_PROCESS",
            "SERVICE_WIN32_SHARE_PROCESS",
        ])),
        ('service_status', EnumProperty(allowed=[
            "SERVICE_CONTINUE_PENDING",
            "SERVICE_PAUSE_PENDING",
            "SERVICE_PAUSED",
            "SERVICE_RUNNING",
            "SERVICE_START_PENDING",
            "SERVICE_STOP_PENDING",
            "SERVICE_STOPPED",
        ])),
    ])


class Process(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716273>`__.
    """  # noqa

    _type = 'process'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('is_hidden', BooleanProperty()),
        ('pid', IntegerProperty()),
        ('name', StringProperty()),
        # this is not the created timestamps of the object itself
        ('created', TimestampProperty()),
        ('cwd', StringProperty()),
        ('arguments', ListProperty(StringProperty)),
        ('command_line', StringProperty()),
        ('environment_variables', DictionaryProperty()),
        ('opened_connection_refs', ListProperty(ObjectReferenceProperty(valid_types='network-traffic'))),
        ('creator_user_ref', ObjectReferenceProperty(valid_types='user-account')),
        ('binary_ref', ObjectReferenceProperty(valid_types='file')),
        ('parent_ref', ObjectReferenceProperty(valid_types='process')),
        ('child_refs', ListProperty(ObjectReferenceProperty('process'))),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])

    def _check_object_constraints(self):
        # no need to check windows-service-ext, since it has a required property
        super(Process, self)._check_object_constraints()
        try:
            self._check_at_least_one_property()
            if "windows-process-ext" in self.get('extensions', {}):
                self.extensions["windows-process-ext"]._check_at_least_one_property()
        except AtLeastOnePropertyError as enclosing_exc:
            if 'extensions' not in self:
                raise enclosing_exc
            else:
                if "windows-process-ext" in self.get('extensions', {}):
                    self.extensions["windows-process-ext"]._check_at_least_one_property()


class Software(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716282>`__.
    """  # noqa

    _type = 'software'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('name', StringProperty(required=True)),
        ('cpe', StringProperty()),
        ('languages', ListProperty(StringProperty)),
        ('vendor', StringProperty()),
        ('version', StringProperty()),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class URL(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716284>`__.
    """  # noqa

    _type = 'url'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('value', StringProperty(required=True)),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class UNIXAccountExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716289>`__.
    """  # noqa

    _type = 'unix-account-ext'
    _properties = OrderedDict()
    _properties.update([
        ('gid', IntegerProperty()),
        ('groups', ListProperty(StringProperty)),
        ('home_dir', StringProperty()),
        ('shell', StringProperty()),
    ])


class UserAccount(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716286>`__.
    """  # noqa

    _type = 'user-account'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('user_id', StringProperty(required=True)),
        ('account_login', StringProperty()),
        ('account_type', StringProperty()),   # open vocab
        ('display_name', StringProperty()),
        ('is_service_account', BooleanProperty()),
        ('is_privileged', BooleanProperty()),
        ('can_escalate_privs', BooleanProperty()),
        ('is_disabled', BooleanProperty()),
        ('account_created', TimestampProperty()),
        ('account_expires', TimestampProperty()),
        ('password_last_changed', TimestampProperty()),
        ('account_first_login', TimestampProperty()),
        ('account_last_login', TimestampProperty()),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


class WindowsRegistryValueType(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716293>`__.
    """  # noqa

    _type = 'windows-registry-value-type'
    _properties = OrderedDict()
    _properties.update([
        ('name', StringProperty(required=True)),
        ('data', StringProperty()),
        ('data_type', EnumProperty(allowed=[
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
        ])),
    ])


class WindowsRegistryKey(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716291>`__.
    """  # noqa

    _type = 'windows-registry-key'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('key', StringProperty(required=True)),
        ('values', ListProperty(EmbeddedObjectProperty(type=WindowsRegistryValueType))),
        # this is not the modified timestamps of the object itself
        ('modified', TimestampProperty()),
        ('creator_user_ref', ObjectReferenceProperty(valid_types='user-account')),
        ('number_of_subkeys', IntegerProperty()),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])

    @property
    def values(self):
        # Needed because 'values' is a property on collections.Mapping objects
        return self._inner['values']


class X509V3ExtenstionsType(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716298>`__.
    """  # noqa

    _type = 'x509-v3-extensions-type'
    _properties = OrderedDict()
    _properties.update([
        ('basic_constraints', StringProperty()),
        ('name_constraints', StringProperty()),
        ('policy_constraints', StringProperty()),
        ('key_usage', StringProperty()),
        ('extended_key_usage', StringProperty()),
        ('subject_key_identifier', StringProperty()),
        ('authority_key_identifier', StringProperty()),
        ('subject_alternative_name', StringProperty()),
        ('issuer_alternative_name', StringProperty()),
        ('subject_directory_attributes', StringProperty()),
        ('crl_distribution_points', StringProperty()),
        ('inhibit_any_policy', StringProperty()),
        ('private_key_usage_period_not_before', TimestampProperty()),
        ('private_key_usage_period_not_after', TimestampProperty()),
        ('certificate_policies', StringProperty()),
        ('policy_mappings', StringProperty()),
    ])


class X509Certificate(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716296>`__.
    """  # noqa

    _type = 'x509-certificate'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('is_self_signed', BooleanProperty()),
        ('hashes', HashesProperty()),
        ('version', StringProperty()),
        ('serial_number', StringProperty()),
        ('signature_algorithm', StringProperty()),
        ('issuer', StringProperty()),
        ('validity_not_before', TimestampProperty()),
        ('validity_not_after', TimestampProperty()),
        ('subject', StringProperty()),
        ('subject_public_key_algorithm', StringProperty()),
        ('subject_public_key_modulus', StringProperty()),
        ('subject_public_key_exponent', IntegerProperty()),
        ('x509_v3_extensions', EmbeddedObjectProperty(type=X509V3ExtenstionsType)),
        ('extensions', ExtensionsProperty(enclosing_type=_type)),
    ])


OBJ_MAP_OBSERVABLE = {
    'artifact': Artifact,
    'autonomous-system': AutonomousSystem,
    'directory': Directory,
    'domain-name': DomainName,
    'email-addr': EmailAddress,
    'email-message': EmailMessage,
    'file': File,
    'ipv4-addr': IPv4Address,
    'ipv6-addr': IPv6Address,
    'mac-addr': MACAddress,
    'mutex': Mutex,
    'network-traffic': NetworkTraffic,
    'process': Process,
    'software': Software,
    'url': URL,
    'user-account': UserAccount,
    'windows-registry-key': WindowsRegistryKey,
    'x509-certificate': X509Certificate,
}


EXT_MAP = {
    'file': {
        'archive-ext': ArchiveExt,
        'ntfs-ext': NTFSExt,
        'pdf-ext': PDFExt,
        'raster-image-ext': RasterImageExt,
        'windows-pebinary-ext': WindowsPEBinaryExt
    },
    'network-traffic': {
        'http-request-ext': HTTPRequestExt,
        'icmp-ext': ICMPExt,
        'socket-ext': SocketExt,
        'tcp-ext': TCPExt,
    },
    'process': {
        'windows-process-ext': WindowsProcessExt,
        'windows-service-ext': WindowsServiceExt,
    },
    'user-account': {
        'unix-account-ext': UNIXAccountExt,
    },
}


def parse_observable(data, _valid_refs=None, allow_custom=False):
    """Deserialize a string or file-like object into a STIX Cyber Observable
    object.

    Args:
        data: The STIX 2 string to be parsed.
        _valid_refs: A list of object references valid for the scope of the
            object being parsed. Use empty list if no valid refs are present.
        allow_custom: Whether to allow custom properties or not.
            Default: False.

    Returns:
        An instantiated Python STIX Cyber Observable object.
    """

    obj = get_dict(data)
    obj['_valid_refs'] = _valid_refs or []

    if 'type' not in obj:
        raise ParseError("Can't parse observable with no 'type' property: %s" % str(obj))
    try:
        obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
    except KeyError:
        raise ParseError("Can't parse unknown observable type '%s'! For custom observables, "
                         "use the CustomObservable decorator." % obj['type'])

    if 'extensions' in obj and obj['type'] in EXT_MAP:
        for name, ext in obj['extensions'].items():
            if name not in EXT_MAP[obj['type']]:
                raise ParseError("Can't parse Unknown extension type '%s' for observable type '%s'!" % (name, obj['type']))
            ext_class = EXT_MAP[obj['type']][name]
            obj['extensions'][name] = ext_class(allow_custom=allow_custom, **obj['extensions'][name])

    return obj_class(allow_custom=allow_custom, **obj)


def _register_observable(new_observable):
    """Register a custom STIX Cyber Observable type.
    """

    OBJ_MAP_OBSERVABLE[new_observable._type] = new_observable


def CustomObservable(type='x-custom-observable', properties=None):
    """Custom STIX Cyber Observable Object type decorator.

    Example:
        >>> @CustomObservable('x-custom-observable', [
        ...     ('property1', StringProperty(required=True)),
        ...     ('property2', IntegerProperty()),
        ... ])
        ... class MyNewObservableType():
        ...     pass
    """

    def custom_builder(cls):

        class _Custom(cls, _Observable):

            _type = type
            _properties = OrderedDict()
            _properties.update([
                ('type', TypeProperty(_type)),
            ])

            if not properties or not isinstance(properties, list):
                raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

            # Check properties ending in "_ref/s" are ObjectReferenceProperties
            for prop_name, prop in properties:
                if prop_name.endswith('_ref') and not isinstance(prop, ObjectReferenceProperty):
                    raise ValueError("'%s' is named like an object reference property but "
                                     "is not an ObjectReferenceProperty." % prop_name)
                elif (prop_name.endswith('_refs') and (not isinstance(prop, ListProperty)
                                                       or not isinstance(prop.contained, ObjectReferenceProperty))):
                    raise ValueError("'%s' is named like an object reference list property but "
                                     "is not a ListProperty containing ObjectReferenceProperty." % prop_name)

            _properties.update(properties)

            def __init__(self, **kwargs):
                _Observable.__init__(self, **kwargs)
                try:
                    cls.__init__(self, **kwargs)
                except (AttributeError, TypeError) as e:
                    # Don't accidentally catch errors raised in a custom __init__()
                    if ("has no attribute '__init__'" in str(e) or
                            str(e) == "object.__init__() takes no parameters"):
                        return
                    raise e

        _register_observable(_Custom)
        return _Custom

    return custom_builder


def _register_extension(observable, new_extension):
    """Register a custom extension to a STIX Cyber Observable type.
    """

    try:
        observable_type = observable._type
    except AttributeError:
        raise ValueError("Unknown observable type. Custom observables must be "
                         "created with the @CustomObservable decorator.")

    try:
        EXT_MAP[observable_type][new_extension._type] = new_extension
    except KeyError:
        if observable_type not in OBJ_MAP_OBSERVABLE:
            raise ValueError("Unknown observable type '%s'. Custom observables "
                             "must be created with the @CustomObservable decorator."
                             % observable_type)
        else:
            EXT_MAP[observable_type] = {new_extension._type: new_extension}


def CustomExtension(observable=None, type='x-custom-observable', properties=None):
    """Decorator for custom extensions to STIX Cyber Observables.
    """

    if not observable or not issubclass(observable, _Observable):
        raise ValueError("'observable' must be a valid Observable class!")

    def custom_builder(cls):

        class _Custom(cls, _Extension):

            _type = type
            _properties = {
                'extensions': ExtensionsProperty(enclosing_type=_type),
            }

            if not isinstance(properties, dict) or not properties:
                raise ValueError("'properties' must be a dict!")

            _properties.update(properties)

            def __init__(self, **kwargs):
                _Extension.__init__(self, **kwargs)
                try:
                    cls.__init__(self, **kwargs)
                except (AttributeError, TypeError) as e:
                    # Don't accidentally catch errors raised in a custom __init__()
                    if ("has no attribute '__init__'" in str(e) or
                            str(e) == "object.__init__() takes no parameters"):
                        return
                    raise e

        _register_extension(observable, _Custom)
        return _Custom

    return custom_builder
