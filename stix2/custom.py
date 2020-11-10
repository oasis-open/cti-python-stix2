from collections import OrderedDict

import six

from .base import _cls_init
from .parsing import (
    _get_extension_class, _register_extension, _register_marking,
    _register_object, _register_observable,
)


def _get_properties_dict(properties):
    try:
        return OrderedDict(properties)
    except TypeError as e:
        six.raise_from(
            ValueError(
                "properties must be dict-like, e.g. a list "
                "containing tuples.  For example, "
                "[('property1', IntegerProperty())]",
            ),
            e,
        )


def _custom_object_builder(cls, type, properties, version, base_class):
    prop_dict = _get_properties_dict(properties)

    class _CustomObject(cls, base_class):

        _type = type
        _properties = prop_dict

        def __init__(self, **kwargs):
            base_class.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)
            ext = getattr(self, 'with_extension', None)
            if ext and version != '2.0':
                if 'extensions' not in self._inner:
                    self._inner['extensions'] = {}
                self._inner['extensions'][ext] = _get_extension_class(ext, version)()

    _CustomObject.__name__ = cls.__name__

    _register_object(_CustomObject, version=version)
    return _CustomObject


def _custom_marking_builder(cls, type, properties, version, base_class):
    prop_dict = _get_properties_dict(properties)

    class _CustomMarking(cls, base_class):

        _type = type
        _properties = prop_dict

        def __init__(self, **kwargs):
            base_class.__init__(self, **kwargs)
            ext = getattr(self, 'with_extension', None)
            if ext and version != '2.0':
                if 'extensions' not in self._inner:
                    self._inner['extensions'] = {}
                self._inner['extensions'][ext] = _get_extension_class(ext, version)()
            _cls_init(cls, self, kwargs)

    _CustomMarking.__name__ = cls.__name__

    _register_marking(_CustomMarking, version=version)
    return _CustomMarking


def _custom_observable_builder(cls, type, properties, version, base_class, id_contrib_props=None):
    if id_contrib_props is None:
        id_contrib_props = []

    prop_dict = _get_properties_dict(properties)

    class _CustomObservable(cls, base_class):

        _type = type
        _properties = prop_dict
        if version != '2.0':
            _id_contributing_properties = id_contrib_props

        def __init__(self, **kwargs):
            base_class.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)
            ext = getattr(self, 'with_extension', None)
            if ext and version != '2.0':
                if 'extensions' not in self._inner:
                    self._inner['extensions'] = {}
                self._inner['extensions'][ext] = _get_extension_class(ext, version)()

    _CustomObservable.__name__ = cls.__name__

    _register_observable(_CustomObservable, version=version)
    return _CustomObservable


def _custom_extension_builder(cls, type, properties, version, base_class):
    prop_dict = _get_properties_dict(properties)

    class _CustomExtension(cls, base_class):

        _type = type
        _properties = prop_dict

        def __init__(self, **kwargs):
            base_class.__init__(self, **kwargs)
            _cls_init(cls, self, kwargs)

    _CustomExtension.__name__ = cls.__name__

    _register_extension(_CustomExtension, version=version)
    return _CustomExtension
