"""Functions and class wrappers for interacting with STIX data at a high level.
"""

from . import AttackPattern as _AttackPattern
from . import Campaign as _Campaign
from . import CourseOfAction as _CourseOfAction
from . import Identity as _Identity
from . import Indicator as _Indicator
from . import IntrusionSet as _IntrusionSet
from . import Malware as _Malware
from . import ObservedData as _ObservedData
from . import Report as _Report
from . import ThreatActor as _ThreatActor
from . import Tool as _Tool
from . import Vulnerability as _Vulnerability
from .environment import Environment
from .sources.filters import Filter
from .sources.memory import MemoryStore

_environ = Environment(store=MemoryStore())

create = _environ.create
get = _environ.get
all_versions = _environ.all_versions
query = _environ.query
creator_of = _environ.creator_of
relationships = _environ.relationships
related_to = _environ.related_to
add = _environ.add
add_filters = _environ.add_filters
add_filter = _environ.add_filter
parse = _environ.parse
add_data_source = _environ.source.add_data_source


# Wrap SDOs with helper functions


STIX_OBJS = [_AttackPattern, _Campaign, _CourseOfAction, _Identity,
             _Indicator, _IntrusionSet, _Malware, _ObservedData, _Report,
             _ThreatActor, _Tool, _Vulnerability]


def created_by_wrapper(self, *args, **kwargs):
    return _environ.creator_of(self, *args, **kwargs)


def relationships_wrapper(self, *args, **kwargs):
    return _environ.relationships(self, *args, **kwargs)


def related_wrapper(self, *args, **kwargs):
    return _environ.related_to(self, *args, **kwargs)


def constructor_wrapper(obj_type):
    # Use an intermediate wrapper class so the implicit environment will create objects that have our wrapper functions
    wrapped_type = type(obj_type.__name__, obj_type.__bases__, dict(
        created_by=created_by_wrapper,
        relationships=relationships_wrapper,
        related=related_wrapper,
        **obj_type.__dict__
    ))

    @staticmethod
    def new_constructor(cls, *args, **kwargs):
        return _environ.create(wrapped_type, *args, **kwargs)
    return new_constructor


# Create wrapper classes whose constructors call the implicit environment's create()
for obj_type in STIX_OBJS:
    new_class = type(obj_type.__name__, (), {})
    new_class.__new__ = constructor_wrapper(obj_type)
    globals()[obj_type.__name__] = new_class


# Functions to get all objects of a specific type


def attack_patterns():
    return query(Filter('type', '=', 'attack-pattern'))


def campaigns():
    return query(Filter('type', '=', 'campaign'))


def courses_of_action():
    return query(Filter('type', '=', 'course-of-action'))


def identities():
    return query(Filter('type', '=', 'identity'))


def indicators():
    return query(Filter('type', '=', 'indicator'))


def intrusion_sets():
    return query(Filter('type', '=', 'intrusion-set'))


def malware():
    return query(Filter('type', '=', 'malware'))


def observed_data():
    return query(Filter('type', '=', 'observed-data'))


def reports():
    return query(Filter('type', '=', 'report'))


def threat_actors():
    return query(Filter('type', '=', 'threat-actor'))


def tools():
    return query(Filter('type', '=', 'tool'))


def vulnerabilities():
    return query(Filter('type', '=', 'vulnerability'))
