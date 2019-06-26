"""STIX 2.1 API Objects.

.. autosummary::
   :toctree: v21

   bundle
   common
   observables
   sdo
   sro

|
"""

# flake8: noqa

from .bundle import Bundle
from .common import (
    TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, CustomMarking, ExternalReference,
    GranularMarking, KillChainPhase, LanguageContent, MarkingDefinition,
    StatementMarking, TLPMarking,
)
from .observables import (
    URL, AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    CustomExtension, CustomObservable, Directory, DomainName, EmailAddress,
    EmailMessage, EmailMIMEComponent, File, HTTPRequestExt, ICMPExt,
    IPv4Address, IPv6Address, MACAddress, Mutex, NetworkTraffic, NTFSExt,
    PDFExt, Process, RasterImageExt, SocketExt, Software, TCPExt,
    UNIXAccountExt, UserAccount, WindowsPEBinaryExt,
    WindowsPEOptionalHeaderType, WindowsPESection, WindowsProcessExt,
    WindowsRegistryKey, WindowsRegistryValueType, WindowsServiceExt,
    X509Certificate, X509V3ExtenstionsType,
)
from .sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Identity, Indicator,
    IntrusionSet, Location, Malware, Note, ObservedData, Opinion, Report,
    ThreatActor, Tool, Vulnerability,
)
from .sro import Relationship, Sighting

OBJ_MAP = {
    'attack-pattern': AttackPattern,
    'bundle': Bundle,
    'campaign': Campaign,
    'course-of-action': CourseOfAction,
    'identity': Identity,
    'indicator': Indicator,
    'intrusion-set': IntrusionSet,
    'language-content': LanguageContent,
    'location': Location,
    'malware': Malware,
    'note': Note,
    'marking-definition': MarkingDefinition,
    'observed-data': ObservedData,
    'opinion': Opinion,
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
        'windows-pebinary-ext': WindowsPEBinaryExt,
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
