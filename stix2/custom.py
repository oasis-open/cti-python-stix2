from collections import OrderedDict
import re

import six

from .base import _cls_init, _Extension, _Observable, _STIXBase
from .core import (
    STIXDomainObject, _register_marking, _register_object,
    _register_observable, _register_observable_extension,
)
from .utils import get_class_hierarchy_names, TYPE_21_REGEX, TYPE_REGEX, PREFIX_21_REGEX


def _custom_object_builder(cls, type, properties, version):
    class _CustomObject(cls, STIXDomainObject):

        if version == "2.0":
            if not re.match(TYPE_REGEX, type):
                raise ValueError(
                    "Invalid type name '%s': must only contain the "
                    "characters a-z (lowercase ASCII), 0-9, and hyphen (-)." %
                    type,
                )
        else:  # 2.1+
            if not re.match(TYPE_21_REGEX, type):
                raise ValueError(
                    "Invalid type name '%s': must only contain the "
                    "characters a-z (lowercase ASCII), 0-9, and hyphen (-) "
                    "and must begin with an a-z character" % type,
                )

        if len(type) < 3 or len(type) > 250:
            raise ValueError(
                "Invalid type name '%s': must be between 3 and 250 characters." % type,
            )

        if not properties or not isinstance(properties, list):
            raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

        if version == "2.1":
            for prop_name, prop in properties:
                if not re.match(PREFIX_21_REGEX, prop_name):
                    raise ValueError("Property name '%s' must begin with an alpha character" % prop_name)

        _type = type
        _properties = OrderedDict(properties)

        def __init__(self, **kwargs):
            _STIXBase.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_object(_CustomObject, version=version)
    return _CustomObject


def _custom_marking_builder(cls, type, properties, version):

    class _CustomMarking(cls, _STIXBase):

        _type = type
        _properties = OrderedDict(properties)

        def __init__(self, **kwargs):
            _STIXBase.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_marking(_CustomMarking, version=version)
    return _CustomMarking


def _custom_observable_builder(cls, type, properties, version, id_contrib_props=None):
    if id_contrib_props is None:
        id_contrib_props = []

    class _CustomObservable(cls, _Observable):

        if version == "2.0":
            if not re.match(TYPE_REGEX, type):
                raise ValueError(
                    "Invalid observable type name '%s': must only contain the "
                    "characters a-z (lowercase ASCII), 0-9, and hyphen (-)." %
                    type,
                )
        else:  # 2.1+
            if not re.match(TYPE_21_REGEX, type):
                raise ValueError(
                    "Invalid observable type name '%s': must only contain the "
                    "characters a-z (lowercase ASCII), 0-9, and hyphen (-) "
                    "and must begin with an a-z character" % type,
                )

        if len(type) < 3 or len(type) > 250:
            raise ValueError("Invalid observable type name '%s': must be between 3 and 250 characters." % type)

        if not properties or not isinstance(properties, list):
            raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

        if version == "2.0":
            # If using STIX2.0, check properties ending in "_ref/s" are ObjectReferenceProperties
            for prop_name, prop in properties:
                if prop_name.endswith('_ref') and ('ObjectReferenceProperty' not in get_class_hierarchy_names(prop)):
                    raise ValueError(
                        "'%s' is named like an object reference property but "
                        "is not an ObjectReferenceProperty." % prop_name,
                    )
                elif (prop_name.endswith('_refs') and ('ListProperty' not in get_class_hierarchy_names(prop) or
                                                       'ObjectReferenceProperty' not in get_class_hierarchy_names(prop.contained))):
                    raise ValueError(
                        "'%s' is named like an object reference list property but "
                        "is not a ListProperty containing ObjectReferenceProperty." % prop_name,
                    )
        else:
            # If using STIX2.1 (or newer...), check properties ending in "_ref/s" are ReferenceProperties
            for prop_name, prop in properties:
                if not re.match(PREFIX_21_REGEX, prop_name):
                    raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)
                elif prop_name.endswith('_ref') and ('ReferenceProperty' not in get_class_hierarchy_names(prop)):
                    raise ValueError(
                        "'%s' is named like a reference property but "
                        "is not a ReferenceProperty." % prop_name,
                    )
                elif (prop_name.endswith('_refs') and ('ListProperty' not in get_class_hierarchy_names(prop) or
                                                       'ReferenceProperty' not in get_class_hierarchy_names(prop.contained))):
                    raise ValueError(
                        "'%s' is named like a reference list property but "
                        "is not a ListProperty containing ReferenceProperty." % prop_name,
                    )

        _type = type
        _properties = OrderedDict(properties)
        if version != '2.0':
            _id_contributing_properties = id_contrib_props

        def __init__(self, **kwargs):
            _Observable.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_observable(_CustomObservable, version=version)
    return _CustomObservable


def _custom_extension_builder(cls, observable, type, properties, version):

    try:
        prop_dict = OrderedDict(properties)
    except TypeError as e:
        six.raise_from(
            ValueError(
                "Extension properties must be dict-like, e.g. a list "
                "containing tuples.  For example, "
                "[('property1', IntegerProperty())]",
            ),
            e,
        )

    class _CustomExtension(cls, _Extension):

        _type = type
        _properties = prop_dict

        def __init__(self, **kwargs):
            _Extension.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _register_observable_extension(observable, _CustomExtension, version=version)
    return _CustomExtension
