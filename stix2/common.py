"""STIX 2 Common Data Types and Properties"""

from collections import OrderedDict

from .other import ExternalReference, GranularMarking
from .properties import (BooleanProperty, ListProperty, ReferenceProperty,
                         StringProperty, TimestampProperty)
from .utils import NOW

COMMON_PROPERTIES = OrderedDict()

COMMON_PROPERTIES.update([
    # 'type' and 'id' should be defined on each individual type
    ('created_by_ref', ReferenceProperty(type="identity")),
    ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
    ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
    ('revoked', BooleanProperty()),
    ('labels', ListProperty(StringProperty)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(type="marking-definition"))),
    ('granular_markings', ListProperty(GranularMarking)),
])
