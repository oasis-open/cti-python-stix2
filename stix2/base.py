"""Base class for type definitions in the stix2 library."""

import collections
import datetime as dt
import json

from .exceptions import ExtraFieldsError, ImmutableError, InvalidValueError, \
                        InvalidObjRefError, MissingFieldsError
from .utils import format_datetime, get_timestamp, NOW

__all__ = ['STIXJSONEncoder', '_STIXBase']

DEFAULT_ERROR = "{type} must have {field}='{expected}'."


class STIXJSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, (dt.date, dt.datetime)):
            return format_datetime(obj)
        elif isinstance(obj, _STIXBase):
            return dict(obj)
        else:
            return super(STIXJSONEncoder, self).default(obj)


def get_required_properties(properties):
    return (k for k, v in properties.items() if v.required)


class _STIXBase(collections.Mapping):
    """Base class for STIX object types"""

    def _check_property(self, prop_name, prop, kwargs):
        if prop_name not in kwargs:
            if hasattr(prop, 'default'):
                value = prop.default()
                if value == NOW:
                    value = self.__now
                kwargs[prop_name] = value

        if prop_name in kwargs:
            try:
                kwargs[prop_name] = prop.clean(kwargs[prop_name])
            except ValueError as exc:
                raise InvalidValueError(self.__class__, prop_name, reason=str(exc))

    def __init__(self, **kwargs):
        cls = self.__class__

        # Use the same timestamp for any auto-generated datetimes
        self.__now = get_timestamp()

        # Detect any keyword arguments not allowed for a specific type
        extra_kwargs = list(set(kwargs) - set(cls._properties))
        if extra_kwargs:
            raise ExtraFieldsError(cls, extra_kwargs)

        # Detect any missing required fields
        required_fields = get_required_properties(cls._properties)
        missing_kwargs = set(required_fields) - set(kwargs)
        if missing_kwargs:
            raise MissingFieldsError(cls, missing_kwargs)

        for prop_name, prop_metadata in cls._properties.items():
            self._check_property(prop_name, prop_metadata, kwargs)

        self._inner = kwargs

        if self.granular_markings:
            for m in self.granular_markings:
                # TODO: check selectors
                pass

    def __getitem__(self, key):
        return self._inner[key]

    def __iter__(self):
        return iter(self._inner)

    def __len__(self):
        return len(self._inner)

    # Handle attribute access just like key access
    def __getattr__(self, name):
        return self.get(name)

    def __setattr__(self, name, value):
        if name != '_inner' and not name.startswith("_STIXBase__"):
            raise ImmutableError
        super(_STIXBase, self).__setattr__(name, value)

    def __str__(self):
        # TODO: put keys in specific order. Probably need custom JSON encoder.
        return json.dumps(self, indent=4, sort_keys=True, cls=STIXJSONEncoder,
                          separators=(",", ": "))  # Don't include spaces after commas.

    def __repr__(self):
        props = [(k, self[k]) for k in sorted(self._properties) if self.get(k)]
        return "{0}({1})".format(self.__class__.__name__,
                                 ", ".join(["{0!s}={1!r}".format(k, v) for k, v in props]))


class Observable(_STIXBase):

    def __init__(self, **kwargs):
        self._STIXBase__valid_refs = kwargs.pop('_valid_refs')
        super(Observable, self).__init__(**kwargs)

    def _check_property(self, prop_name, prop, kwargs):
        super(Observable, self)._check_property(prop_name, prop, kwargs)
        if prop_name.endswith('_ref'):
            ref = kwargs[prop_name].split('--', 1)[0]
            if ref not in self._STIXBase__valid_refs:
                raise InvalidObjRefError(self.__class__, prop_name, "'%s' is not a valid object in local scope" % ref)
        if prop_name.endswith('_refs'):
            for r in kwargs[prop_name]:
                ref = r.split('--', 1)[0]
                if ref not in self._STIXBase__valid_refs:
                    raise InvalidObjRefError(self.__class__, prop_name, "'%s' is not a valid object in local scope" % ref)
        # TODO also check the type of the object referenced, not just that the key exists
