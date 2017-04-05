"""Python APIs for STIX 2."""

# flake8: noqa

import json

from .bundle import Bundle
from .common import ExternalReference, KillChainPhase
from .sdo import AttackPattern, Campaign, CourseOfAction, Identity, Indicator, \
    IntrusionSet, Malware, ObservedData, Report, ThreatActor, Tool, \
    Vulnerability
from .sro import Relationship


def parse(data):
    """Deserialize a string or file-like object into a STIX object"""

    try:
        obj = json.loads(data)
    except TypeError:
        obj = json.load(data)

    if 'type' not in obj:
        # TODO parse external references, kill chain phases, and granular markings
        pass
    elif obj['type'] == 'malware':
        return sdo.Malware(**obj)

    return obj
