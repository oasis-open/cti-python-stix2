import collections
import datetime
import json
import uuid

import pytz

DEFAULT_ERROR = "{type} must have {field}='{expected}'."
COMMON_PROPERTIES = {
    'type': {
        'default': (lambda x: x._type),
        'validate': (lambda x, val: val == x._type)
    },
    'id': {
        'default': (lambda x: x._make_id()),
        'validate': (lambda x, val: val.startswith(x._type + "--")),
        'expected': (lambda x: x._type + "--"),
        'error_msg': "{type} {field} values must begin with '{expected}'."
    },
    'created': {},
    'modified': {},
}


def format_datetime(dt):
    # TODO: how to handle naive datetime

    # 1. Convert to UTC
    # 2. Format in isoformat
    # 3. Strip off "+00:00"
    # 4. Add "Z"

    # TODO: how to handle timestamps with subsecond 0's
    return dt.astimezone(pytz.utc).isoformat()[:-6] + "Z"


class STIXJSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
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

    @classmethod
    def _check_kwargs(cls, **kwargs):
        class_name = cls.__name__

        for prop_name, prop_metadata in cls._properties.items():
            if prop_name not in kwargs:
                if prop_metadata.get('default'):
                    kwargs[prop_name] = prop_metadata['default'](cls)
                elif prop_metadata.get('fixed'):
                    kwargs[prop_name] = prop_metadata['fixed']

            if prop_metadata.get('validate'):
                if not prop_metadata['validate'](cls, kwargs[prop_name]):
                    msg = prop_metadata.get('error_msg', DEFAULT_ERROR).format(
                        type=class_name,
                        field=prop_name,
                        expected=prop_metadata.get('expected',
                                                   prop_metadata['default'])(cls),
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

        return kwargs

    def __init__(self, **kwargs):
        # TODO: move all of this back into init, once we check the right things
        # in the right order, or move after the unexpected check.
        kwargs = self._check_kwargs(**kwargs)

        # Detect any keyword arguments not allowed for a specific type
        extra_kwargs = list(set(kwargs) - set(self.__class__._properties))
        if extra_kwargs:
            raise TypeError("unexpected keyword arguments: " + str(extra_kwargs))

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


class Bundle(_STIXBase):

    _type = 'bundle'
    _properties = {
        # Borrow the 'type' and 'id' definitions
        'type': COMMON_PROPERTIES['type'],
        'id': COMMON_PROPERTIES['id'],
        'spec_version': {
            'fixed': "2.0",
        },
        'objects': {},
    }

    def __init__(self, *args, **kwargs):
        # Add any positional arguments to the 'objects' kwarg.
        if args:
            kwargs['objects'] = kwargs.get('objects', []) + list(args)

        super(Bundle, self).__init__(**kwargs)


class Indicator(_STIXBase):

    _type = 'indicator'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {},
        'pattern': {},
        'valid_from': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - revoked
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - name
        # - description
        # - valid_until
        # - kill_chain_phases

        # TODO: do we care about the performance penalty of creating this
        # if we won't need it?
        now = datetime.datetime.now(tz=pytz.UTC)

        # TODO: remove once we check all the fields in the right order
        kwargs = self._check_kwargs(**kwargs)

        if not kwargs.get('labels'):
            raise ValueError("Missing required field for Indicator: 'labels'.")

        if not kwargs.get('pattern'):
            raise ValueError("Missing required field for Indicator: 'pattern'.")

        kwargs.update({
            'created': kwargs.get('created', now),
            'modified': kwargs.get('modified', now),
            'valid_from': kwargs.get('valid_from', now),
        })
        super(Indicator, self).__init__(**kwargs)


class Malware(_STIXBase):

    _type = 'malware'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {},
        'name': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - revoked
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - kill_chain_phases

        # TODO: do we care about the performance penalty of creating this
        # if we won't need it?
        now = datetime.datetime.now(tz=pytz.UTC)

        # TODO: remove once we check all the fields in the right order
        kwargs = self._check_kwargs(**kwargs)

        if not kwargs.get('labels'):
            raise ValueError("Missing required field for Malware: 'labels'.")

        if not kwargs.get('name'):
            raise ValueError("Missing required field for Malware: 'name'.")

        kwargs.update({
            'created': kwargs.get('created', now),
            'modified': kwargs.get('modified', now),
        })
        super(Malware, self).__init__(**kwargs)


class Relationship(_STIXBase):

    _type = 'relationship'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'relationship_type': {},
        'source_ref': {},
        'target_ref': {},
    })

    # Explicitly define the first three kwargs to make readable Relationship declarations.
    def __init__(self, source_ref=None, relationship_type=None, target_ref=None,
                 **kwargs):
        # TODO:
        # - created_by_ref
        # - revoked
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description

        # TODO: remove once we check all the fields in the right order
        kwargs = self._check_kwargs(**kwargs)

        if source_ref and not kwargs.get('source_ref'):
            kwargs['source_ref'] = source_ref
        if relationship_type and not kwargs.get('relationship_type'):
            kwargs['relationship_type'] = relationship_type
        if target_ref and not kwargs.get('target_ref'):
            kwargs['target_ref'] = target_ref

        # TODO: do we care about the performance penalty of creating this
        # if we won't need it?
        now = datetime.datetime.now(tz=pytz.UTC)

        if not kwargs.get('relationship_type'):
            raise ValueError("Missing required field for Relationship: 'relationship_type'.")

        if not kwargs.get('source_ref'):
            raise ValueError("Missing required field for Relationship: 'source_ref'.")
        elif isinstance(kwargs['source_ref'], _STIXBase):
            kwargs['source_ref'] = kwargs['source_ref'].id

        if not kwargs.get('target_ref'):
            raise ValueError("Missing required field for Relationship: 'target_ref'.")
        elif isinstance(kwargs['target_ref'], _STIXBase):
            kwargs['target_ref'] = kwargs['target_ref'].id

        kwargs.update({
            'created': kwargs.get('created', now),
            'modified': kwargs.get('modified', now),
            'relationship_type': kwargs['relationship_type'],
            'target_ref': kwargs['target_ref'],
        })

        super(Relationship, self).__init__(**kwargs)
