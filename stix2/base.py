"""Base class for type definitions in the stix2 library."""

import collections
import datetime as dt
import json
import uuid

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


class _STIXBase(collections.Mapping):
    """Base class for STIX object types"""

    @classmethod
    def _make_id(cls):
        return cls._type + "--" + str(uuid.uuid4())

    def __init__(self, **kwargs):
        cls = self.__class__
        class_name = cls.__name__

        # Use the same timestamp for any auto-generated datetimes
        now = get_timestamp()

        # Detect any keyword arguments not allowed for a specific type
        extra_kwargs = list(set(kwargs) - set(cls._properties))
        if extra_kwargs:
            raise TypeError("unexpected keyword arguments: " + str(extra_kwargs))

        required_fields = [k for k, v in cls._properties.items() if v.get('required')]
        missing_kwargs = set(required_fields) - set(kwargs)
        if missing_kwargs:
            msg = "Missing required field(s) for {type}: ({fields})."
            field_list = ", ".join(x for x in sorted(list(missing_kwargs)))
            raise ValueError(msg.format(type=class_name, fields=field_list))

        for prop_name, prop_metadata in cls._properties.items():
            if prop_name not in kwargs:
                if prop_metadata.get('default'):
                    default = prop_metadata['default']
                    if default == NOW:
                        kwargs[prop_name] = now
                    else:
                        kwargs[prop_name] = default(cls)
                elif prop_metadata.get('fixed'):
                    kwargs[prop_name] = prop_metadata['fixed']

            if prop_metadata.get('validate'):
                if (prop_name in kwargs and
                        not prop_metadata['validate'](cls, kwargs[prop_name])):
                    msg = prop_metadata.get('error_msg', DEFAULT_ERROR).format(
                        type=class_name,
                        field=prop_name,
                        expected=prop_metadata.get('expected',
                                                   prop_metadata.get('default', lambda x: ''))(cls),
                    )
                    raise ValueError(msg)
            elif prop_metadata.get('fixed'):
                if kwargs[prop_name] != prop_metadata['fixed']:
                    msg = prop_metadata.get('error_msg', DEFAULT_ERROR).format(
                        type=class_name,
                        field=prop_name,
                        expected=prop_metadata['fixed']
                    )
                    raise ValueError(msg)

        self._inner = kwargs

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
        if name != '_inner':
            raise ValueError("Cannot modify properties after creation.")
        super(_STIXBase, self).__setattr__(name, value)

    def __str__(self):
        # TODO: put keys in specific order. Probably need custom JSON encoder.
        return json.dumps(self, indent=4, sort_keys=True, cls=STIXJSONEncoder,
                          separators=(",", ": "))  # Don't include spaces after commas.

    def __repr__(self):
        props = [(k, self[k]) for k in sorted(self._properties) if self.get(k)]
        return "{0}({1})".format(self.__class__.__name__,
                                 ", ".join(["{0!s}={1!r}".format(k, v) for k, v in props]))
