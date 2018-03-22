"""Functions and class wrappers for interacting with STIX data at a high level.

.. autofunction:: create
.. autofunction:: set_default_creator
.. autofunction:: set_default_created
.. autofunction:: set_default_external_refs
.. autofunction:: set_default_object_marking_refs
.. autofunction:: get
.. autofunction:: all_versions
.. autofunction:: query
.. autofunction:: query_by_type
.. autofunction:: creator_of
.. autofunction:: relationships
.. autofunction:: related_to
.. autofunction:: add
.. autofunction:: add_filters
.. autofunction:: add_filter
.. autofunction:: parse
.. autofunction:: add_data_source
.. autofunction:: add_data_sources

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
from . import (AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,  # noqa: F401
               Bundle, CustomExtension, CustomMarking, CustomObservable,
               Directory, DomainName, EmailAddress, EmailMessage,
               EmailMIMEComponent, Environment, ExtensionsProperty,
               ExternalReference, File, FileSystemSource, Filter,
               GranularMarking, HTTPRequestExt, ICMPExt, IPv4Address,
               IPv6Address, KillChainPhase, MACAddress, MarkingDefinition,
               MemoryStore, Mutex, NetworkTraffic, NTFSExt, parse_observable,
               PDFExt, Process, RasterImageExt, Relationship, Sighting,
               SocketExt, Software, StatementMarking, TAXIICollectionSource,
               TCPExt, TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, TLPMarking,
               UNIXAccountExt, URL, UserAccount, WindowsPEBinaryExt,
               WindowsPEOptionalHeaderType, WindowsPESection,
               WindowsProcessExt, WindowsRegistryKey, WindowsRegistryValueType,
               WindowsServiceExt, X509Certificate, X509V3ExtenstionsType)

# Use an implicit MemoryStore
_environ = Environment(store=MemoryStore())

create = _environ.create
set_default_creator = _environ.set_default_creator
set_default_created = _environ.set_default_created
set_default_external_refs = _environ.set_default_external_refs
set_default_object_marking_refs = _environ.set_default_object_marking_refs
get = _environ.get
all_versions = _environ.all_versions
query = _environ.query
query_by_type = _environ.query_by_type
creator_of = _environ.creator_of
relationships = _environ.relationships
related_to = _environ.related_to
add = _environ.add
add_filters = _environ.add_filters
add_filter = _environ.add_filter
parse = _environ.parse
add_data_source = _environ.source.add_data_source
add_data_sources = _environ.source.add_data_sources


# Wrap SDOs with helper functions


STIX_OBJS = [_AttackPattern, _Campaign, _CourseOfAction, _Identity,
             _Indicator, _IntrusionSet, _Malware, _ObservedData, _Report,
             _ThreatActor, _Tool, _Vulnerability]

STIX_OBJ_DOCS = """

.. method:: created_by(*args, **kwargs)

        {}

.. method:: relationships(*args, **kwargs)

        {}

.. method:: related(*args, **kwargs)

        {}

""".format(_environ.creator_of.__doc__,
           _environ.relationships.__doc__,
           _environ.related_to.__doc__)


def _created_by_wrapper(self, *args, **kwargs):
    return _environ.creator_of(self, *args, **kwargs)


def _relationships_wrapper(self, *args, **kwargs):
    return _environ.relationships(self, *args, **kwargs)


def _related_wrapper(self, *args, **kwargs):
    return _environ.related_to(self, *args, **kwargs)


def _constructor_wrapper(obj_type):
    # Use an intermediate wrapper class so the implicit environment will create objects that have our wrapper functions
    wrapped_type = type(obj_type.__name__, obj_type.__bases__, dict(
        created_by=_created_by_wrapper,
        relationships=_relationships_wrapper,
        related=_related_wrapper,
        **obj_type.__dict__
    ))

    @staticmethod
    def new_constructor(cls, *args, **kwargs):
        return _environ.create(wrapped_type, *args, **kwargs)
    return new_constructor


# Create wrapper classes whose constructors call the implicit environment's create()
for obj_type in STIX_OBJS:
    new_class_dict = {
        '__new__': _constructor_wrapper(obj_type),
        '__doc__': 'Workbench wrapper around the `{0} <stix2.v20.sdo.html#stix2.v20.sdo.{0}>`__. object. {1}'.format(obj_type.__name__, STIX_OBJ_DOCS)
    }
    new_class = type(obj_type.__name__, (), new_class_dict)

    globals()[obj_type.__name__] = new_class
    new_class = None


# Functions to get all objects of a specific type


def attack_patterns(filters=None):
    """Retrieve all Attack Pattern objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('attack-pattern', filters)


def campaigns(filters=None):
    """Retrieve all Campaign objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('campaign', filters)


def courses_of_action(filters=None):
    """Retrieve all Course of Action objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('course-of-action', filters)


def identities(filters=None):
    """Retrieve all Identity objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('identity', filters)


def indicators(filters=None):
    """Retrieve all Indicator objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('indicator', filters)


def intrusion_sets(filters=None):
    """Retrieve all Intrusion Set objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('intrusion-set', filters)


def malware(filters=None):
    """Retrieve all Malware objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('malware', filters)


def observed_data(filters=None):
    """Retrieve all Observed Data objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('observed-data', filters)


def reports(filters=None):
    """Retrieve all Report objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('report', filters)


def threat_actors(filters=None):
    """Retrieve all Threat Actor objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('threat-actor', filters)


def tools(filters=None):
    """Retrieve all Tool objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('tool', filters)


def vulnerabilities(filters=None):
    """Retrieve all Vulnerability objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    return query_by_type('vulnerability', filters)
