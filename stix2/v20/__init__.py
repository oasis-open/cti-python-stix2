
# flake8: noqa

from ..core import Bundle
from .common import (TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, CustomMarking,
                     ExternalReference, GranularMarking, KillChainPhase,
                     MarkingDefinition, StatementMarking, TLPMarking)
from .observables import (URL, AlternateDataStream, ArchiveExt, Artifact,
                          AutonomousSystem, CustomExtension, CustomObservable,
                          Directory, DomainName, EmailAddress, EmailMessage,
                          EmailMIMEComponent, ExtensionsProperty, File,
                          HTTPRequestExt, ICMPExt, IPv4Address, IPv6Address,
                          MACAddress, Mutex, NetworkTraffic, NTFSExt, PDFExt,
                          Process, RasterImageExt, SocketExt, Software, TCPExt,
                          UNIXAccountExt, UserAccount, WindowsPEBinaryExt,
                          WindowsPEOptionalHeaderType, WindowsPESection,
                          WindowsProcessExt, WindowsRegistryKey,
                          WindowsRegistryValueType, WindowsServiceExt,
                          X509Certificate, X509V3ExtenstionsType,
                          parse_observable)
from .sdo import (AttackPattern, Campaign, CourseOfAction, CustomObject,
                  Identity, Indicator, IntrusionSet, Malware, ObservedData,
                  Report, ThreatActor, Tool, Vulnerability)
from .sro import Relationship, Sighting

OBJ_MAP = {
    'attack-pattern': AttackPattern,
    'bundle': Bundle,
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
