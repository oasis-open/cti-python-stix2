"""Functions and class wrappers for interacting with STIX2 data at a high level.

.. autofunction:: create
.. autofunction:: set_default_creator
.. autofunction:: set_default_created
.. autofunction:: set_default_external_refs
.. autofunction:: set_default_object_marking_refs
.. autofunction:: get
.. autofunction:: all_versions
.. autofunction:: query
.. autofunction:: creator_of
.. autofunction:: relationships
.. autofunction:: related_to
.. autofunction:: save
.. autofunction:: add_filters
.. autofunction:: add_filter
.. autofunction:: parse
.. autofunction:: add_data_source
.. autofunction:: add_data_sources

"""

import stix2
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
from . import (  # noqa: F401
    AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    Bundle, CustomExtension, CustomMarking, CustomObservable,
    Directory, DomainName, EmailAddress, EmailMessage,
    EmailMIMEComponent, Environment, ExternalReference, File,
    FileSystemSource, Filter, GranularMarking, HTTPRequestExt,
    ICMPExt, IPv4Address, IPv6Address, KillChainPhase, MACAddress,
    MarkingDefinition, MemoryStore, Mutex, NetworkTraffic, NTFSExt,
    parse_observable, PDFExt, Process, RasterImageExt, Relationship,
    Sighting, SocketExt, Software, StatementMarking,
    TAXIICollectionSource, TCPExt, TLP_AMBER, TLP_GREEN, TLP_RED,
    TLP_WHITE, TLPMarking, UNIXAccountExt, URL, UserAccount,
    WindowsPEBinaryExt, WindowsPEOptionalHeaderType,
    WindowsPESection, WindowsProcessExt, WindowsRegistryKey,
    WindowsRegistryValueType, WindowsServiceExt, X509Certificate,
    X509V3ExtenstionsType
)
from .datastore.filters import FilterSet

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
creator_of = _environ.creator_of
relationships = _environ.relationships
related_to = _environ.related_to
save = _environ.add
add_filters = _environ.add_filters
add_filter = _environ.add_filter
parse = _environ.parse
add_data_source = _environ.source.add_data_source
add_data_sources = _environ.source.add_data_sources


# Wrap SDOs with helper functions


STIX_OBJS = [
    _AttackPattern, _Campaign, _CourseOfAction, _Identity,
    _Indicator, _IntrusionSet, _Malware, _ObservedData, _Report,
    _ThreatActor, _Tool, _Vulnerability,
]

STIX_OBJ_DOCS = """

.. method:: created_by(*args, **kwargs)

        {}

.. method:: relationships(*args, **kwargs)

        {}

.. method:: related(*args, **kwargs)

        {}

""".format(
    _environ.creator_of.__doc__,
    _environ.relationships.__doc__,
    _environ.related_to.__doc__
)


def _created_by_wrapper(self, *args, **kwargs):
    return _environ.creator_of(self, *args, **kwargs)


def _relationships_wrapper(self, *args, **kwargs):
    return _environ.relationships(self, *args, **kwargs)


def _related_wrapper(self, *args, **kwargs):
    return _environ.related_to(self, *args, **kwargs)


def _observed_data_init(self, *args, **kwargs):
    self.__allow_custom = kwargs.get('allow_custom', False)
    self._properties['objects'].allow_custom = kwargs.get('allow_custom', False)
    super(self.__class__, self).__init__(*args, **kwargs)


def _constructor_wrapper(obj_type):
    # Use an intermediate wrapper class so the implicit environment will create objects that have our wrapper functions
    class_dict = dict(
        created_by=_created_by_wrapper,
        relationships=_relationships_wrapper,
        related=_related_wrapper,
        **obj_type.__dict__
    )

    # Avoid TypeError about super() in ObservedData
    if 'ObservedData' in obj_type.__name__:
        class_dict['__init__'] = _observed_data_init

    wrapped_type = type(obj_type.__name__, obj_type.__bases__, class_dict)

    @staticmethod
    def new_constructor(cls, *args, **kwargs):
        x = _environ.create(wrapped_type, *args, **kwargs)
        return x
    return new_constructor


def _setup_workbench():
    # Create wrapper classes whose constructors call the implicit environment's create()
    for obj_type in STIX_OBJS:
        new_class_dict = {
            '__new__': _constructor_wrapper(obj_type),
            '__doc__': 'Workbench wrapper around the `{0} <stix2.v20.sdo.rst#stix2.v20.sdo.{0}>`__ object. {1}'.format(obj_type.__name__, STIX_OBJ_DOCS),
        }
        new_class = type(obj_type.__name__, (), new_class_dict)

        # Add our new class to this module's globals and to the library-wide mapping.
        # This allows parse() to use the wrapped classes.
        globals()[obj_type.__name__] = new_class
        stix2.OBJ_MAP[obj_type._type] = new_class
        new_class = None


_setup_workbench()


# Functions to get all objects of a specific type


def attack_patterns(filters=None):
    """Retrieve all Attack Pattern objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'attack-pattern'))
    return query(filter_list)


def campaigns(filters=None):
    """Retrieve all Campaign objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'campaign'))
    return query(filter_list)


def courses_of_action(filters=None):
    """Retrieve all Course of Action objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'course-of-action'))
    return query(filter_list)


def identities(filters=None):
    """Retrieve all Identity objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'identity'))
    return query(filter_list)


def indicators(filters=None):
    """Retrieve all Indicator objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'indicator'))
    return query(filter_list)


def intrusion_sets(filters=None):
    """Retrieve all Intrusion Set objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'intrusion-set'))
    return query(filter_list)


def malware(filters=None):
    """Retrieve all Malware objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'malware'))
    return query(filter_list)


def observed_data(filters=None):
    """Retrieve all Observed Data objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'observed-data'))
    return query(filter_list)


def reports(filters=None):
    """Retrieve all Report objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'report'))
    return query(filter_list)


def threat_actors(filters=None):
    """Retrieve all Threat Actor objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'threat-actor'))
    return query(filter_list)


def tools(filters=None):
    """Retrieve all Tool objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'tool'))
    return query(filter_list)


def vulnerabilities(filters=None):
    """Retrieve all Vulnerability objects.

    Args:
        filters (list, optional): A list of additional filters to apply to
            the query.

    """
    filter_list = FilterSet(filters)
    filter_list.add(Filter('type', '=', 'vulnerability'))
    return query(filter_list)
