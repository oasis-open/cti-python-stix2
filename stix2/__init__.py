"""Python APIs for STIX 2.

.. autosummary::
   :toctree: api

   core
   datastore
   environment
   exceptions
   markings
   patterns
   properties
   utils
   v20.common
   v20.observables
   v20.sdo
   v20.sro
"""

# flake8: noqa

from .core import Bundle, _collect_stix2_obj_maps, _register_type, parse
from .datastore import CompositeDataSource
from .datastore.filesystem import (FileSystemSink, FileSystemSource,
                                   FileSystemStore)
from .datastore.filters import Filter
from .datastore.memory import MemorySink, MemorySource, MemoryStore
from .datastore.taxii import (TAXIICollectionSink, TAXIICollectionSource,
                              TAXIICollectionStore)
from .environment import Environment, ObjectFactory
from .markings import (add_markings, clear_markings, get_markings, is_marked,
                       remove_markings, set_markings)
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
                       StartStopQualifier, StringConstant, TimestampConstant,
                       WithinQualifier)
from .utils import get_dict, new_version, revoke
from .v20 import *  # This import will always be the latest STIX 2.X version
from .version import __version__

_collect_stix2_obj_maps()

DEFAULT_VERSION = "2.0"  # Default version will always be the latest STIX 2.X version
