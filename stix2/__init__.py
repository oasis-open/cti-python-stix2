"""Python APIs for STIX 2."""

# flake8: noqa

from . import exceptions
from .bundle import Bundle
from .observables import (URL, Artifact, AutonomousSystem, Directory,
                          DomainName, EmailAddress, EmailMessage, EmailMIMEComponent, File,
                          IPv4Address, IPv6Address, MACAddress, Mutex,
                          NetworkTraffic, Process, Software, UserAccount,
                          WindowsRegistryKey, X509Certificate)
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


def parse(data):
    """Deserialize a string or file-like object into a STIX object"""

    obj = get_dict(data)

    if 'type' not in obj:
        # TODO parse external references, kill chain phases, and granular markings
        pass
    else:
        try:
            obj_class = OBJ_MAP[obj['type']]
        except KeyError:
            # TODO handle custom objects
            raise ValueError("Can't parse unknown object type '%s'!" % obj['type'])
        return obj_class(**obj)

    return obj


def parse_observable(data, _valid_refs):
    """Deserialize a string or file-like object into a STIX Cyber Observable
    object.
    """

    obj = get_dict(data)
    obj['_valid_refs'] = _valid_refs

    if 'type' not in obj:
        raise ValueError("'type' is a required field!")
    try:
        obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
    except KeyError:
        # TODO handle custom objects
        raise ValueError("Can't parse unknown object type '%s'!" % obj['type'])
    return obj_class(**obj)
