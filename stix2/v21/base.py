"""Base classes for STIX 2.1 type definitions."""

from ..base import (
    _DomainObject, _Extension, _Observable, _RelationshipObject, _STIXBase,
)


class _STIXBase21(_STIXBase):

    def __init__(self, **kwargs):
        if 'extensions' in self._properties:
            self._properties['extensions'].allow_custom = kwargs.get('allow_custom', False)
        super(_STIXBase21, self).__init__(**kwargs)


class _Observable(_Observable, _STIXBase21):
    pass


class _Extension(_Extension, _STIXBase21):
    pass


class _DomainObject(_DomainObject, _STIXBase21):
    pass


class _RelationshipObject(_RelationshipObject, _STIXBase21):
    pass
