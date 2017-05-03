"""Python APIs for STIX 2."""

# flake8: noqa

from .bundle import Bundle
from .observables import Artifact, File
from .other import ExternalReference, KillChainPhase, MarkingDefinition, \
    GranularMarking, StatementMarking, TLPMarking
from .sdo import AttackPattern, Campaign, CourseOfAction, Identity, Indicator, \
    IntrusionSet, Malware, ObservedData, Report, ThreatActor, Tool, \
    Vulnerability
from .sro import Relationship, Sighting
from .utils import get_dict
from . import exceptions


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
    'file': File,
}


def parse(data, observable=False):
    """Deserialize a string or file-like object into a STIX object"""

    obj = get_dict(data)

    if 'type' not in obj:
        # TODO parse external references, kill chain phases, and granular markings
        pass
    else:
        try:
            if observable:
                obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
            else:
                obj_class = OBJ_MAP[obj['type']]
        except KeyError:
            # TODO handle custom objects
            raise ValueError("Can't parse unknown object type '%s'!" % obj['type'])
        return obj_class(**obj)

    return obj
