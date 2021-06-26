"""Base classes for STIX 2.1 type definitions."""

from ..base import (
    _DomainObject, _Extension, _Observable, _RelationshipObject, _STIXBase,
)


class _STIXBase21(_STIXBase):
    pass


class _Observable(_Observable, _STIXBase21):

    def __init__(self, **kwargs):
        super(_Observable, self).__init__(**kwargs)
        if 'id' not in kwargs:
            # Specific to 2.1+ observables: generate a deterministic ID
            id_ = self._generate_id()

            # Spec says fall back to UUIDv4 if no contributing properties were
            # given.  That's what already happened (the following is actually
            # overwriting the default uuidv4), so nothing to do here.
            if id_ is not None:
                # Can't assign to self (we're immutable), so slip the ID in
                # more sneakily.
                self._inner["id"] = id_


class _Extension(_Extension, _STIXBase21):
    extension_type = None

    def __init__(self, **kwargs):
        super(_Extension, self).__init__(**kwargs)
        if getattr(self, "extension_type", None):
            self._inner["extension_type"] = self.extension_type

    def _check_at_least_one_property(self, list_of_properties=None):
        new_ext_check = getattr(self, "extension_type", None)

        if new_ext_check is None:
            super(_Extension, self)._check_at_least_one_property(list_of_properties=list_of_properties)


class _DomainObject(_DomainObject, _STIXBase21):
    pass


class _RelationshipObject(_RelationshipObject, _STIXBase21):
    pass
