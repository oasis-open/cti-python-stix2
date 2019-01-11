"""Python APIs for STIX 2.

.. autosummary::
   :toctree: api

   confidence
   core
   datastore
   environment
   exceptions
   markings
   patterns
   properties
   utils
   v20
   v21
   workbench

"""

# flake8: noqa

from .confidence import scales
from .core import _collect_stix2_mappings, parse, parse_observable
from .datastore import CompositeDataSource
from .datastore.filesystem import (
    FileSystemSink, FileSystemSource, FileSystemStore,
)
from .datastore.filters import Filter
from .datastore.memory import MemorySink, MemorySource, MemoryStore
from .datastore.taxii import (
    TAXIICollectionSink, TAXIICollectionSource, TAXIICollectionStore,
)
from .environment import Environment, ObjectFactory
from .markings import (
    add_markings, clear_markings, get_markings, is_marked, remove_markings,
    set_markings,
)
from .patterns import (
    AndBooleanExpression, AndObservationExpression, BasicObjectPathComponent,
    BinaryConstant, BooleanConstant, EqualityComparisonExpression,
    FloatConstant, FollowedByObservationExpression,
    GreaterThanComparisonExpression, GreaterThanEqualComparisonExpression,
    HashConstant, HexConstant, InComparisonExpression, IntegerConstant,
    IsSubsetComparisonExpression, IsSupersetComparisonExpression,
    LessThanComparisonExpression, LessThanEqualComparisonExpression,
    LikeComparisonExpression, ListConstant, ListObjectPathComponent,
    MatchesComparisonExpression, ObjectPath, ObservationExpression,
    OrBooleanExpression, OrObservationExpression, ParentheticalExpression,
    QualifiedObservationExpression, ReferenceObjectPathComponent,
    RepeatQualifier, StartStopQualifier, StringConstant, TimestampConstant,
    WithinQualifier,
)
from .utils import new_version, revoke
from .v20 import *  # This import will always be the latest STIX 2.X version
from .version import __version__

_collect_stix2_mappings()

DEFAULT_VERSION = '2.0'  # Default version will always be the latest STIX 2.X version
