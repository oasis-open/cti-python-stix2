from collections import OrderedDict
import re

from .base import _cls_init, _Extension, _Observable, _STIXBase
from .core import (
    STIXDomainObject, _register_marking, _register_object,
    _register_observable, _register_observable_extension,
)
from .utils import TYPE_REGEX, get_class_hierarchy_names


def _custom_object_builder(cls, type, properties, version):
    class _CustomObject(cls, STIXDomainObject):

        if not re.match(TYPE_REGEX, type):
            raise ValueError(
                "Invalid type name '%s': must only contain the "
                "characters a-z (lowercase ASCII), 0-9, and hyphen (-)." % type,
            )
        elif len(type) < 3 or len(type) > 250:
            raise ValueError(
                "Invalid type name '%s': must be between 3 and 250 characters." % type,
            )

        if not properties or not isinstance(properties, list):
            raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

        _type = type
        _properties = OrderedDict(properties)

        def __init__(self, **kwargs):
            _STIXBase.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_object(_CustomObject, version=version)
    return _CustomObject


def _custom_marking_builder(cls, type, properties, version):
    class _CustomMarking(cls, _STIXBase):

        if not properties or not isinstance(properties, list):
            raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

        _type = type
        _properties = OrderedDict(properties)

        def __init__(self, **kwargs):
            _STIXBase.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_marking(_CustomMarking, version=version)
    return _CustomMarking


def _custom_observable_builder(cls, type, properties, version):
    class _CustomObservable(cls, _Observable):

        if not re.match(TYPE_REGEX, type):
            raise ValueError(
                "Invalid observable type name '%s': must only contain the "
                "characters a-z (lowercase ASCII), 0-9, and hyphen (-)." % type,
            )
        elif len(type) < 3 or len(type) > 250:
            raise ValueError("Invalid observable type name '%s': must be between 3 and 250 characters." % type)

        if not properties or not isinstance(properties, list):
            raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

        # Check properties ending in "_ref/s" are ObjectReferenceProperties
        for prop_name, prop in properties:
            if prop_name.endswith('_ref') and ('ObjectReferenceProperty' not in get_class_hierarchy_names(prop)):
                raise ValueError(
                    "'%s' is named like an object reference property but "
                    "is not an ObjectReferenceProperty." % prop_name,
                )
            elif (prop_name.endswith('_refs') and ('ListProperty' not in get_class_hierarchy_names(prop)
                                                   or 'ObjectReferenceProperty' not in get_class_hierarchy_names(prop.contained))):
                raise ValueError(
                    "'%s' is named like an object reference list property but "
                    "is not a ListProperty containing ObjectReferenceProperty." % prop_name,
                )

        _type = type
        _properties = OrderedDict(properties)

        def __init__(self, **kwargs):
            _Observable.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_observable(_CustomObservable, version=version)
    return _CustomObservable


def _custom_extension_builder(cls, observable, type, properties, version):
    if not observable or not issubclass(observable, _Observable):
        raise ValueError("'observable' must be a valid Observable class!")

    class _CustomExtension(cls, _Extension):

        if not re.match(TYPE_REGEX, type):
            raise ValueError(
                "Invalid extension type name '%s': must only contain the "
                "characters a-z (lowercase ASCII), 0-9, and hyphen (-)." % type,
            )
        elif len(type) < 3 or len(type) > 250:
            raise ValueError("Invalid extension type name '%s': must be between 3 and 250 characters." % type)

        if not properties or not isinstance(properties, list):
            raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

        _type = type
        _properties = OrderedDict(properties)

        def __init__(self, **kwargs):
            _Extension.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_observable_extension(observable, _CustomExtension, version=version)
    return _CustomExtension
