"""Python APIs for STIX 2."""

# flake8: noqa

from . import exceptions
from .bundle import Bundle
from .observables import (URL, AlternateDataStream, ArchiveExt, Artifact,
                          AutonomousSystem, Directory, DomainName,
                          EmailAddress, EmailMessage, EmailMIMEComponent, File,
                          HTTPRequestExt, ICMPExt, IPv4Address, IPv6Address,
                          MACAddress, Mutex, NetworkTraffic, NTFSExt, PDFExt,
                          Process, RasterImageExt, SocketExt, Software, TCPExt,
                          UNIXAccountExt, UserAccount, WindowsPEBinaryExt,
                          WindowsPEOptionalHeaderType, WindowsPESection,
                          WindowsProcessExt, WindowsRegistryKey,
                          WindowsRegistryValueType, WindowsServiceExt,
                          X509Certificate, X509V3ExtenstionsType)
from .other import (ExternalReference, GranularMarking, KillChainPhase,
                    MarkingDefinition, StatementMarking, TLPMarking)
from .sdo import (AttackPattern, Campaign, CourseOfAction, Identity, Indicator,
                  IntrusionSet, Malware, ObservedData, Report, ThreatActor,
                  Tool, Vulnerability)
from .sro import Relationship, Sighting
from .utils import get_dict

OBJ_MAP = {
    'attack-pattern': AttackPattern,
    'campaign': Campaign,
    'course-of-action': CourseOfAction,
    'identity': Identity,
    'indicator': Indicator,
    'intrusion-set': IntrusionSet,
    'malware': Malware,
    'marking-definition': MarkingDefinition,
    'observed-data': ObservedData,
    'report': Report,
    'relationship': Relationship,
    'threat-actor': ThreatActor,
    'tool': Tool,
    'sighting': Sighting,
    'vulnerability': Vulnerability,
}

OBJ_MAP_OBSERVABLE = {
    'artifact': Artifact,
    'autonomous-system': AutonomousSystem,
    'directory': Directory,
    'domain-name': DomainName,
    'email-address': EmailAddress,
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

EXT_MAP_FILE = {
    'archive-ext': ArchiveExt,
    'ntfs-ext': NTFSExt,
    'pdf-ext': PDFExt,
    'raster-image-ext': RasterImageExt,
    'windows-pebinary-ext': WindowsPEBinaryExt
}

EXT_MAP_NETWORK_TRAFFIC = {
    'http-request-ext': HTTPRequestExt,
    'icmp-ext': ICMPExt,
    'socket-ext': SocketExt,
    'tcp-ext': TCPExt,
}

EXT_MAP_PROCESS = {
    'windows-process-ext': WindowsProcessExt,
    'windows-service-ext': WindowsServiceExt,
}

EXT_MAP_USER_ACCOUNT = {
    'unix-account-ext': UNIXAccountExt,
}

EXT_MAP = {
    'file': EXT_MAP_FILE,
    'network-traffic': EXT_MAP_NETWORK_TRAFFIC,
    'process': EXT_MAP_PROCESS,
    'user-account': EXT_MAP_USER_ACCOUNT,

}


def parse(data, allow_custom=False):
    """Deserialize a string or file-like object into a STIX object.

    Args:
        data: The STIX 2 string to be parsed.
        allow_custom (bool): Whether to allow custom properties or not. Default: False.

    Returns:
        An instantiated Python STIX object.
    """

    obj = get_dict(data)

    if 'type' not in obj:
        raise exceptions.ParseError("Can't parse object with no 'type' property: %s" % str(obj))

    try:
        obj_class = OBJ_MAP[obj['type']]
    except KeyError:
        # TODO handle custom objects
        raise exceptions.ParseError("Can't parse unknown object type '%s'!" % obj['type'])
    return obj_class(allow_custom=allow_custom, **obj)


def parse_observable(data, _valid_refs, allow_custom=False):
    """Deserialize a string or file-like object into a STIX Cyber Observable object.

    Args:
        data: The STIX 2 string to be parsed.
        _valid_refs: A list of object references valid for the scope of the object being parsed.
        allow_custom: Whether to allow custom properties or not. Default: False.

    Returns:
        An instantiated Python STIX Cyber Observable object.
    """

    obj = get_dict(data)
    obj['_valid_refs'] = _valid_refs

    if 'type' not in obj:
        raise exceptions.ParseError("Can't parse object with no 'type' property: %s" % str(obj))
    try:
        obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
    except KeyError:
        # TODO handle custom observable objects
        raise exceptions.ParseError("Can't parse unknown object type '%s'!" % obj['type'])

    if 'extensions' in obj and obj['type'] in EXT_MAP:
        for name, ext in obj['extensions'].items():
            if name not in EXT_MAP[obj['type']]:
                raise exceptions.ParseError("Can't parse Unknown extension type '%s' for object type '%s'!" % (name, obj['type']))
            ext_class = EXT_MAP[obj['type']][name]
            obj['extensions'][name] = ext_class(allow_custom=allow_custom, **obj['extensions'][name])

    return obj_class(allow_custom=allow_custom, **obj)
