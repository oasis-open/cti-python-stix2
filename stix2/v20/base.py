"""Base classes for STIX 2.0 type definitions."""

from ..base import _Extension, _Observable, _STIXBase
from ..core import STIXDomainObject, STIXRelationshipObject


class _STIXBase20(_STIXBase):
    _spec_version = "2.0"


class _Observable(_Observable, _STIXBase20):
    pass


class _Extension(_Extension, _STIXBase20):
    pass


class STIXDomainObject(STIXDomainObject, _STIXBase20):
    pass


class STIXRelationshipObject(STIXRelationshipObject, _STIXBase20):
    pass
