"""Python APIs for STIX 2."""

# flake8: noqa

from . import exceptions
from .bundle import Bundle
from .environment import ObjectFactory
from .observables import (URL, AlternateDataStream, ArchiveExt, Artifact,
                          AutonomousSystem, CustomObservable, Directory,
                          DomainName, EmailAddress, EmailMessage,
                          EmailMIMEComponent, File, HTTPRequestExt, ICMPExt,
                          IPv4Address, IPv6Address, MACAddress, Mutex,
                          NetworkTraffic, NTFSExt, PDFExt, Process,
                          RasterImageExt, SocketExt, Software, TCPExt,
                          UNIXAccountExt, UserAccount, WindowsPEBinaryExt,
                          WindowsPEOptionalHeaderType, WindowsPESection,
                          WindowsProcessExt, WindowsRegistryKey,
                          WindowsRegistryValueType, WindowsServiceExt,
                          X509Certificate, X509V3ExtenstionsType,
                          parse_observable)
from .other import (TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE,
                    ExternalReference, GranularMarking, KillChainPhase,
                    MarkingDefinition, StatementMarking, TLPMarking)
from .patterns import (AndBooleanExpression, AndObservationExpression,
                       BasicObjectPathComponent, EqualityComparisonExpression,
                       FloatConstant, FollowedByObservationExpression,
                       GreaterThanComparisonExpression,
                       GreaterThanEqualComparisonExpression, HashConstant,
                       HexConstant, IntegerConstant,
                       IsSubsetComparisonExpression,
                       IsSupersetComparisonExpression,
                       LessThanComparisonExpression,
                       LessThanEqualComparisonExpression,
                       LikeComparisonExpression, ListConstant,
                       ListObjectPathComponent, MatchesComparisonExpression,
                       ObjectPath, ObservationExpression, OrBooleanExpression,
                       OrObservationExpression, ParentheticalExpression,
                       QualifiedObservationExpression,
                       ReferenceObjectPathComponent, RepeatQualifier,
                       StartStopQualifier, StringConstant, TimestampConstant, WithinQualifier)
from .sdo import (AttackPattern, Campaign, CourseOfAction, CustomObject,
                  Identity, Indicator, IntrusionSet, Malware, ObservedData,
                  Report, ThreatActor, Tool, Vulnerability)
from .sro import Relationship, Sighting
from .utils import get_dict
from .version import __version__

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
        raise exceptions.ParseError("Can't parse unknown object type '%s'! For custom types, use the CustomObject decorator." % obj['type'])
    return obj_class(allow_custom=allow_custom, **obj)


def _register_type(new_type):
    """Register a custom STIX Object type.
    """

    OBJ_MAP[new_type._type] = new_type
