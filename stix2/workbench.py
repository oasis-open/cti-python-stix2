"""Functions and class wrappers for interacting with STIX data at a high level.
"""

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
