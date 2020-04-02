"""STIX 2.1 Cyber Observable Objects.

Embedded observable object types, such as Email MIME Component, which is
embedded in Email Message objects, inherit from ``_STIXBase21`` instead of
_Observable and do not have a ``_type`` attribute.
"""

from collections import OrderedDict
import itertools

from ..custom import _custom_extension_builder, _custom_observable_builder
from ..exceptions import AtLeastOnePropertyError, DependentPropertiesError
from ..properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    ObjectReferenceProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from .base import _Extension, _Observable, _STIXBase21
from .common import GranularMarking


class Artifact(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_rqwyxo6gp7cv>`__.
    """

    _type = 'artifact'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('mime_type', StringProperty()),
        ('payload_bin', BinaryProperty()),
        ('url', StringProperty()),
        ('hashes', HashesProperty(spec_version='2.1')),
        ('encryption_algorithm', StringProperty()),
        ('decryption_key', StringProperty()),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["hashes", "payload_bin"]

    def _check_object_constraints(self):
        super(Artifact, self)._check_object_constraints()
        self._check_mutually_exclusive_properties(['payload_bin', 'url'])
        self._check_properties_dependency(['hashes'], ['url'])


class AutonomousSystem(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_bxebwa6l91fb>`__.
    """

    _type = 'autonomous-system'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('number', IntegerProperty(required=True)),
        ('name', StringProperty()),
        ('rir', StringProperty()),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["number"]


class Directory(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_vhpkn06q7fvl>`__.
    """

    _type = 'directory'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('path', StringProperty(required=True)),
        ('path_enc', StringProperty()),
        # these are not the created/modified timestamps of the object itself
        ('ctime', TimestampProperty()),
        ('mtime', TimestampProperty()),
        ('atime', TimestampProperty()),
        ('contains_refs', ListProperty(ReferenceProperty(valid_types=['file', 'directory'], spec_version='2.1'))),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["path"]


class DomainName(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_i2zf5h7vnrd9>`__.
    """

    _type = 'domain-name'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('resolves_to_refs', ListProperty(ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'domain-name'], spec_version='2.1'))),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["value"]


class EmailAddress(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_am7srelb9c14>`__.
    """

    _type = 'email-addr'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('display_name', StringProperty()),
        ('belongs_to_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["value"]


class EmailMIMEComponent(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_kzv52qqc0xw1>`__.
    """

    _properties = OrderedDict([
        ('body', StringProperty()),
        ('body_raw_ref', ObjectReferenceProperty(valid_types=['artifact', 'file'])),
        ('content_type', StringProperty()),
        ('content_disposition', StringProperty()),
    ])

    def _check_object_constraints(self):
        super(EmailMIMEComponent, self)._check_object_constraints()
        self._check_at_least_one_property(['body', 'body_raw_ref'])


class EmailMessage(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_loz634bn09om>`__.
    """

    _type = 'email-message'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('is_multipart', BooleanProperty(required=True)),
        ('date', TimestampProperty()),
        ('content_type', StringProperty()),
        ('from_ref', ReferenceProperty(valid_types='email-addr', spec_version='2.1')),
        ('sender_ref', ReferenceProperty(valid_types='email-addr', spec_version='2.1')),
        ('to_refs', ListProperty(ReferenceProperty(valid_types='email-addr', spec_version='2.1'))),
        ('cc_refs', ListProperty(ReferenceProperty(valid_types='email-addr', spec_version='2.1'))),
        ('bcc_refs', ListProperty(ReferenceProperty(valid_types='email-addr', spec_version='2.1'))),
        ('message_id', StringProperty()),
        ('subject', StringProperty()),
        ('received_lines', ListProperty(StringProperty)),
        ('additional_header_fields', DictionaryProperty(spec_version='2.1')),
        ('body', StringProperty()),
        ('body_multipart', ListProperty(EmbeddedObjectProperty(type=EmailMIMEComponent))),
        ('raw_email_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["from_ref", "subject", "body"]

    def _check_object_constraints(self):
        super(EmailMessage, self)._check_object_constraints()
        self._check_properties_dependency(['is_multipart'], ['body_multipart'])
        if self.get('is_multipart') is True and self.get('body'):
            # 'body' MAY only be used if is_multipart is false.
            raise DependentPropertiesError(self.__class__, [('is_multipart', 'body')])


class ArchiveExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mm25z9wuw4tr>`__.
    """

    _type = 'archive-ext'
    _properties = OrderedDict([
        ('contains_refs', ListProperty(ObjectReferenceProperty(valid_types=['file', 'directory']), required=True)),
        ('comment', StringProperty()),
    ])


class AlternateDataStream(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_nbqgazg6fsma>`__.
    """

    _properties = OrderedDict([
        ('name', StringProperty(required=True)),
        ('hashes', HashesProperty(spec_version='2.1')),
        ('size', IntegerProperty()),
    ])


class NTFSExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_tb77nk1g3y6f>`__.
    """

    _type = 'ntfs-ext'
    _properties = OrderedDict([
        ('sid', StringProperty()),
        ('alternate_data_streams', ListProperty(EmbeddedObjectProperty(type=AlternateDataStream))),
    ])


class PDFExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_30hzxqrmkg8w>`__.
    """

    _type = 'pdf-ext'
    _properties = OrderedDict([
        ('version', StringProperty()),
        ('is_optimized', BooleanProperty()),
        ('document_info_dict', DictionaryProperty(spec_version='2.1')),
        ('pdfid0', StringProperty()),
        ('pdfid1', StringProperty()),
    ])


class RasterImageExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_20mnz0u5ppxr>`__.
    """

    _type = 'raster-image-ext'
    _properties = OrderedDict([
        ('image_height', IntegerProperty()),
        ('image_width', IntegerProperty()),
        ('bits_per_pixel', IntegerProperty()),
        ('exif_tags', DictionaryProperty(spec_version='2.1')),
    ])


class WindowsPEOptionalHeaderType(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_wyp5qdc2wugy>`__.
    """

    _properties = OrderedDict([
        ('magic_hex', HexProperty()),
        ('major_linker_version', IntegerProperty()),
        ('minor_linker_version', IntegerProperty()),
        ('size_of_code', IntegerProperty(min=0)),
        ('size_of_initialized_data', IntegerProperty(min=0)),
        ('size_of_uninitialized_data', IntegerProperty(min=0)),
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
        ('size_of_image', IntegerProperty(min=0)),
        ('size_of_headers', IntegerProperty(min=0)),
        ('checksum_hex', HexProperty()),
        ('subsystem_hex', HexProperty()),
        ('dll_characteristics_hex', HexProperty()),
        ('size_of_stack_reserve', IntegerProperty(min=0)),
        ('size_of_stack_commit', IntegerProperty(min=0)),
        ('size_of_heap_reserve', IntegerProperty()),
        ('size_of_heap_commit', IntegerProperty()),
        ('loader_flags_hex', HexProperty()),
        ('number_of_rva_and_sizes', IntegerProperty()),
        ('hashes', HashesProperty(spec_version='2.1')),
    ])

    def _check_object_constraints(self):
        super(WindowsPEOptionalHeaderType, self)._check_object_constraints()
        self._check_at_least_one_property()


class WindowsPESection(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_wiqw87xsov3t>`__.
    """

    _properties = OrderedDict([
        ('name', StringProperty(required=True)),
        ('size', IntegerProperty(min=0)),
        ('entropy', FloatProperty()),
        ('hashes', HashesProperty(spec_version='2.1')),
    ])


class WindowsPEBinaryExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_5f9bgdmj91h5>`__.
    """

    _type = 'windows-pebinary-ext'
    _properties = OrderedDict([
        ('pe_type', StringProperty(required=True)),  # open_vocab
        ('imphash', StringProperty()),
        ('machine_hex', HexProperty()),
        ('number_of_sections', IntegerProperty(min=0)),
        ('time_date_stamp', TimestampProperty(precision='second')),
        ('pointer_to_symbol_table_hex', HexProperty()),
        ('number_of_symbols', IntegerProperty(min=0)),
        ('size_of_optional_header', IntegerProperty(min=0)),
        ('characteristics_hex', HexProperty()),
        ('file_header_hashes', HashesProperty(spec_version='2.1')),
        ('optional_header', EmbeddedObjectProperty(type=WindowsPEOptionalHeaderType)),
        ('sections', ListProperty(EmbeddedObjectProperty(type=WindowsPESection))),
    ])


class File(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_vq03pryd7u32>`__.
    """

    _type = 'file'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('hashes', HashesProperty(spec_version='2.1')),
        ('size', IntegerProperty(min=0)),
        ('name', StringProperty()),
        ('name_enc', StringProperty()),
        ('magic_number_hex', HexProperty()),
        ('mime_type', StringProperty()),
        # these are not the created/modified timestamps of the object itself
        ('ctime', TimestampProperty()),
        ('mtime', TimestampProperty()),
        ('atime', TimestampProperty()),
        ('parent_directory_ref', ReferenceProperty(valid_types='directory', spec_version='2.1')),
        ('contains_refs', ListProperty(ReferenceProperty(valid_types=["SCO"], spec_version='2.1'))),
        ('content_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["hashes", "name", "parent_directory_ref", "extensions"]

    def _check_object_constraints(self):
        super(File, self)._check_object_constraints()
        self._check_at_least_one_property(['hashes', 'name'])


class IPv4Address(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_ta83c412bfsc>`__.
    """

    _type = 'ipv4-addr'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('resolves_to_refs', ListProperty(ReferenceProperty(valid_types='mac-addr', spec_version='2.1'))),
        ('belongs_to_refs', ListProperty(ReferenceProperty(valid_types='autonomous-system', spec_version='2.1'))),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["value"]


class IPv6Address(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_f76hsv2pvwwq>`__.
    """

    _type = 'ipv6-addr'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('resolves_to_refs', ListProperty(ReferenceProperty(valid_types='mac-addr', spec_version='2.1'))),
        ('belongs_to_refs', ListProperty(ReferenceProperty(valid_types='autonomous-system', spec_version='2.1'))),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["value"]


class MACAddress(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_6lhrrdef8852>`__.
    """

    _type = 'mac-addr'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["value"]


class Mutex(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_u65ia5eoc7cv>`__.
    """

    _type = 'mutex'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('name', StringProperty(required=True)),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["name"]


class HTTPRequestExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_60k6dn28qicj>`__.
    """

    _type = 'http-request-ext'
    _properties = OrderedDict([
        ('request_method', StringProperty(required=True)),
        ('request_value', StringProperty(required=True)),
        ('request_version', StringProperty()),
        ('request_header', DictionaryProperty(spec_version='2.1')),
        ('message_body_length', IntegerProperty()),
        ('message_body_data_ref', ObjectReferenceProperty(valid_types='artifact')),
    ])


class ICMPExt(_Extension):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_3g6wds21zwzl>`__.
    """

    _type = 'icmp-ext'
    _properties = OrderedDict([
        ('icmp_type_hex', HexProperty(required=True)),
        ('icmp_code_hex', HexProperty(required=True)),
    ])


class SocketExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_f54f1hripxsg>`__.
    """

    _type = 'socket-ext'
    _properties = OrderedDict([
        (
            'address_family', EnumProperty(
                allowed=[
                    "AF_UNSPEC",
                    "AF_INET",
                    "AF_IPX",
                    "AF_APPLETALK",
                    "AF_NETBIOS",
                    "AF_INET6",
                    "AF_IRDA",
                    "AF_BTH",
                ], required=True,
            ),
        ),
        ('is_blocking', BooleanProperty()),
        ('is_listening', BooleanProperty()),
        (
            'protocol_family', EnumProperty(allowed=[
                "PF_INET",
                "PF_IPX",
                "PF_APPLETALK",
                "PF_INET6",
                "PF_AX25",
                "PF_NETROM",
            ]),
        ),
        ('options', DictionaryProperty(spec_version='2.1')),
        (
            'socket_type', EnumProperty(allowed=[
                "SOCK_STREAM",
                "SOCK_DGRAM",
                "SOCK_RAW",
                "SOCK_RDM",
                "SOCK_SEQPACKET",
            ]),
        ),
        ('socket_descriptor', IntegerProperty(min=0)),
        ('socket_handle', IntegerProperty()),
    ])

    def _check_object_constraints(self):
        super(SocketExt, self)._check_object_constraints()

        options = self.get('options')

        if options is not None:
            acceptable_prefixes = ["SO_", "ICMP_", "ICMP6_", "IP_", "IPV6_", "MCAST_", "TCP_", "IRLMP_"]
            for key, val in options.items():
                if key[:key.find('_') + 1] not in acceptable_prefixes:
                    raise ValueError("Incorrect options key")
                if not isinstance(val, int):
                    raise ValueError("Options value must be an integer")


class TCPExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_2z78x4m8ewcw>`__.
    """

    _type = 'tcp-ext'
    _properties = OrderedDict([
        ('src_flags_hex', HexProperty()),
        ('dst_flags_hex', HexProperty()),
    ])


class NetworkTraffic(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_e5nyr5squmsd>`__.
    """

    _type = 'network-traffic'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('start', TimestampProperty()),
        ('end', TimestampProperty()),
        ('is_active', BooleanProperty()),
        ('src_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'], spec_version='2.1')),
        ('dst_ref', ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'], spec_version='2.1')),
        ('src_port', IntegerProperty(min=0, max=65535)),
        ('dst_port', IntegerProperty(min=0, max=65535)),
        ('protocols', ListProperty(StringProperty, required=True)),
        ('src_byte_count', IntegerProperty(min=0)),
        ('dst_byte_count', IntegerProperty(min=0)),
        ('src_packets', IntegerProperty(min=0)),
        ('dst_packets', IntegerProperty(min=0)),
        ('ipfix', DictionaryProperty(spec_version='2.1')),
        ('src_payload_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('dst_payload_ref', ReferenceProperty(valid_types='artifact', spec_version='2.1')),
        ('encapsulates_refs', ListProperty(ReferenceProperty(valid_types='network-traffic', spec_version='2.1'))),
        ('encapsulated_by_ref', ReferenceProperty(valid_types='network-traffic', spec_version='2.1')),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["start", "src_ref", "dst_ref", "src_port", "dst_port", "protocols"]

    def _check_object_constraints(self):
        super(NetworkTraffic, self)._check_object_constraints()
        self._check_at_least_one_property(['src_ref', 'dst_ref'])

        start = self.get('start')
        end = self.get('end')
        is_active = self.get('is_active')

        if end and is_active is not False:
            msg = "{0.id} 'is_active' must be False if 'end' is present"
            raise ValueError(msg.format(self))

        if end and is_active is True:
            msg = "{0.id} if 'is_active' is True, 'end' must not be included"
            raise ValueError(msg.format(self))

        if start and end and end <= start:
            msg = "{0.id} 'end' must be greater than 'start'"
            raise ValueError(msg.format(self))


class WindowsProcessExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_4wfs4ve800kf>`__.
    """

    _type = 'windows-process-ext'
    _properties = OrderedDict([
        ('aslr_enabled', BooleanProperty()),
        ('dep_enabled', BooleanProperty()),
        ('priority', StringProperty()),
        ('owner_sid', StringProperty()),
        ('window_title', StringProperty()),
        ('startup_info', DictionaryProperty(spec_version='2.1')),
        (
            'integrity_level', EnumProperty(allowed=[
                "low",
                "medium",
                "high",
                "system",
            ]),
        ),
    ])


class WindowsServiceExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_s2rmoe7djlt>`__.
    """

    _type = 'windows-service-ext'
    _properties = OrderedDict([
        ('service_name', StringProperty()),
        ('descriptions', ListProperty(StringProperty)),
        ('display_name', StringProperty()),
        ('group_name', StringProperty()),
        (
            'start_type', EnumProperty(allowed=[
                "SERVICE_AUTO_START",
                "SERVICE_BOOT_START",
                "SERVICE_DEMAND_START",
                "SERVICE_DISABLED",
                "SERVICE_SYSTEM_ALERT",
            ]),
        ),
        ('service_dll_refs', ListProperty(ObjectReferenceProperty(valid_types='file'))),
        (
            'service_type', EnumProperty(allowed=[
                "SERVICE_KERNEL_DRIVER",
                "SERVICE_FILE_SYSTEM_DRIVER",
                "SERVICE_WIN32_OWN_PROCESS",
                "SERVICE_WIN32_SHARE_PROCESS",
            ]),
        ),
        (
            'service_status', EnumProperty(allowed=[
                "SERVICE_CONTINUE_PENDING",
                "SERVICE_PAUSE_PENDING",
                "SERVICE_PAUSED",
                "SERVICE_RUNNING",
                "SERVICE_START_PENDING",
                "SERVICE_STOP_PENDING",
                "SERVICE_STOPPED",
            ]),
        ),
    ])


class Process(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_ur7snm473t1d>`__.
    """

    _type = 'process'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('is_hidden', BooleanProperty()),
        ('pid', IntegerProperty()),
        # this is not the created timestamps of the object itself
        ('created_time', TimestampProperty()),
        ('cwd', StringProperty()),
        ('command_line', StringProperty()),
        ('environment_variables', DictionaryProperty(spec_version='2.1')),
        ('opened_connection_refs', ListProperty(ReferenceProperty(valid_types='network-traffic', spec_version='2.1'))),
        ('creator_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('image_ref', ReferenceProperty(valid_types='file', spec_version='2.1')),
        ('parent_ref', ReferenceProperty(valid_types='process', spec_version='2.1')),
        ('child_refs', ListProperty(ReferenceProperty(valid_types='process', spec_version='2.1'))),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = []

    def _check_object_constraints(self):
        # no need to check windows-service-ext, since it has a required property
        super(Process, self)._check_object_constraints()
        try:
            self._check_at_least_one_property()
            if 'windows-process-ext' in self.get('extensions', {}):
                self.extensions['windows-process-ext']._check_at_least_one_property()
        except AtLeastOnePropertyError as enclosing_exc:
            if 'extensions' not in self:
                raise enclosing_exc
            else:
                if 'windows-process-ext' in self.get('extensions', {}):
                    self.extensions['windows-process-ext']._check_at_least_one_property()


class Software(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_jru33yeokrmh>`__.
    """

    _type = 'software'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('name', StringProperty(required=True)),
        ('cpe', StringProperty()),
        ('swid', StringProperty()),
        ('languages', ListProperty(StringProperty)),
        ('vendor', StringProperty()),
        ('version', StringProperty()),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["name", "cpe", "swid", "vendor", "version"]


class URL(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_6bsklda6vc0c>`__.
    """

    _type = 'url'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["value"]


class UNIXAccountExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_z25gmwyz67kl>`__.
    """

    _type = 'unix-account-ext'
    _properties = OrderedDict([
        ('gid', IntegerProperty()),
        ('groups', ListProperty(StringProperty)),
        ('home_dir', StringProperty()),
        ('shell', StringProperty()),
    ])


class UserAccount(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_hah33g4ntxnx>`__.
    """

    _type = 'user-account'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('user_id', StringProperty()),
        ('credential', StringProperty()),
        ('account_login', StringProperty()),
        ('account_type', StringProperty()),   # open vocab
        ('display_name', StringProperty()),
        ('is_service_account', BooleanProperty()),
        ('is_privileged', BooleanProperty()),
        ('can_escalate_privs', BooleanProperty()),
        ('is_disabled', BooleanProperty()),
        ('account_created', TimestampProperty()),
        ('account_expires', TimestampProperty()),
        ('credential_last_changed', TimestampProperty()),
        ('account_first_login', TimestampProperty()),
        ('account_last_login', TimestampProperty()),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["account_type", "user_id", "account_login"]


class WindowsRegistryValueType(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_6jiqabgqp2hp>`__.
    """

    _type = 'windows-registry-value-type'
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('data', StringProperty()),
        (
            'data_type', EnumProperty(allowed=[
                "REG_NONE",
                "REG_SZ",
                "REG_EXPAND_SZ",
                "REG_BINARY",
                "REG_DWORD",
                "REG_DWORD_BIG_ENDIAN",
                "REG_LINK",
                "REG_MULTI_SZ",
                "REG_RESOURCE_LIST",
                "REG_FULL_RESOURCE_DESCRIPTION",
                "REG_RESOURCE_REQUIREMENTS_LIST",
                "REG_QWORD",
                "REG_INVALID_TYPE",
            ]),
        ),
    ])


class WindowsRegistryKey(_Observable):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_bdim4of4dl37>`__.
    """

    _type = 'windows-registry-key'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('key', StringProperty()),
        ('values', ListProperty(EmbeddedObjectProperty(type=WindowsRegistryValueType))),
        # this is not the modified timestamps of the object itself
        ('modified_time', TimestampProperty()),
        ('creator_user_ref', ReferenceProperty(valid_types='user-account', spec_version='2.1')),
        ('number_of_subkeys', IntegerProperty()),
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["key", "values"]


class X509V3ExtenstionsType(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_c1kt4dheb6vz>`__.
    """

    _type = 'x509-v3-extensions-type'
    _properties = OrderedDict([
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
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_g3kniyun8ykv>`__.
    """

    _type = 'x509-certificate'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('is_self_signed', BooleanProperty()),
        ('hashes', HashesProperty(spec_version='2.1')),
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
        ('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
    ])
    _id_contributing_properties = ["hashes", "serial_number"]

    def _check_object_constraints(self):
        super(X509Certificate, self)._check_object_constraints()

        att_list = [
                'is_self_signed', 'hashes', 'version', 'serial_number',
                'signature_algorithm', 'issuer', 'validity_not_before',
                'validity_not_after', 'subject', 'subject_public_key_algorithm',
                'subject_public_key_modulus', 'subject_public_key_exponent',
                'x509_v3_extensions',
        ]
        self._check_at_least_one_property(att_list)


def CustomObservable(type='x-custom-observable', properties=None, id_contrib_props=None):
    """Custom STIX Cyber Observable Object type decorator.

    Example:
        >>> from stix2.v21 import CustomObservable
        >>> from stix2.properties import IntegerProperty, StringProperty
        >>> @CustomObservable('x-custom-observable', [
        ...     ('property1', StringProperty(required=True)),
        ...     ('property2', IntegerProperty()),
        ... ])
        ... class MyNewObservableType():
        ...     pass

    """
    def wrapper(cls):
        _properties = list(itertools.chain.from_iterable([
            [('type', TypeProperty(type, spec_version='2.1'))],
            [('id', IDProperty(type, spec_version='2.1'))],
            properties,
            [('extensions', ExtensionsProperty(spec_version='2.1', enclosing_type=type))],
        ]))
        return _custom_observable_builder(cls, type, _properties, '2.1', _Observable, id_contrib_props)
    return wrapper


def CustomExtension(observable=None, type='x-custom-observable-ext', properties=None):
    """Decorator for custom extensions to STIX Cyber Observables.
    """
    def wrapper(cls):
        return _custom_extension_builder(cls, observable, type, properties, '2.1', _Extension)
    return wrapper
