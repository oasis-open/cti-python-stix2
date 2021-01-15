import re

import stix2
import stix2.registry

from .base import _DomainObject, _Observable
from .exceptions import DuplicateRegistrationError
from .utils import PREFIX_21_REGEX, get_class_hierarchy_names


def _register_object(new_type, version=stix2.DEFAULT_VERSION):
    """Register a custom STIX Object type.

    Args:
        new_type (class): A class to register in the Object map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    Raises:
        ValueError: If the class being registered wasn't created with the
            @CustomObject decorator.
        DuplicateRegistrationError: If the class has already been registered.

    """

    if not issubclass(new_type, _DomainObject):
        raise ValueError(
            "'%s' must be created with the @CustomObject decorator." %
            new_type.__name__,
        )

    properties = new_type._properties

    if version == "2.1":
        for prop_name, prop in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character" % prop_name)

    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP = stix2.registry.STIX2_OBJ_MAPS[v]['objects']
    if new_type._type in OBJ_MAP.keys():
        raise DuplicateRegistrationError("STIX Object", new_type._type)
    OBJ_MAP[new_type._type] = new_type


def _register_marking(new_marking, version=stix2.DEFAULT_VERSION):
    """Register a custom STIX Marking Definition type.

    Args:
        new_marking (class): A class to register in the Marking map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """

    mark_type = new_marking._type
    properties = new_marking._properties

    stix2.properties._validate_type(mark_type, version)

    if version == "2.1":
        for prop_name, prop_value in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)

    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP_MARKING = stix2.registry.STIX2_OBJ_MAPS[v]['markings']
    if mark_type in OBJ_MAP_MARKING.keys():
        raise DuplicateRegistrationError("STIX Marking", mark_type)
    OBJ_MAP_MARKING[mark_type] = new_marking


def _register_observable(new_observable, version=stix2.DEFAULT_VERSION):
    """Register a custom STIX Cyber Observable type.

    Args:
        new_observable (class): A class to register in the Observables map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    properties = new_observable._properties

    if version == "2.0":
        # If using STIX2.0, check properties ending in "_ref/s" are ObjectReferenceProperties
        for prop_name, prop in properties.items():
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
        for prop_name, prop in properties.items():
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

    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP_OBSERVABLE = stix2.registry.STIX2_OBJ_MAPS[v]['observables']
    if new_observable._type in OBJ_MAP_OBSERVABLE.keys():
        raise DuplicateRegistrationError("Cyber Observable", new_observable._type)
    OBJ_MAP_OBSERVABLE[new_observable._type] = new_observable


def _register_observable_extension(
    observable, new_extension, version=stix2.DEFAULT_VERSION,
):
    """Register a custom extension to a STIX Cyber Observable type.

    Args:
        observable: An observable class or instance
        new_extension (class): A class to register in the Observables
            Extensions map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1").
            Defaults to the latest supported version.

    """
    obs_class = observable if isinstance(observable, type) else \
        type(observable)
    ext_type = new_extension._type
    properties = new_extension._properties

    if not issubclass(obs_class, _Observable):
        raise ValueError("'observable' must be a valid Observable class!")

    stix2.properties._validate_type(ext_type, version)

    if not new_extension._properties:
        raise ValueError(
            "Invalid extension: must define at least one property: " +
            ext_type,
        )

    if version == "2.1":
        if not ext_type.endswith('-ext'):
            raise ValueError(
                "Invalid extension type name '%s': must end with '-ext'." %
                ext_type,
            )

        for prop_name, prop_value in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)

    v = 'v' + version.replace('.', '')

    try:
        observable_type = observable._type
    except AttributeError:
        raise ValueError(
            "Unknown observable type. Custom observables must be "
            "created with the @CustomObservable decorator.",
        )

    OBJ_MAP_OBSERVABLE = stix2.registry.STIX2_OBJ_MAPS[v]['observables']
    EXT_MAP = stix2.registry.STIX2_OBJ_MAPS[v]['observable-extensions']

    try:
        if ext_type in EXT_MAP[observable_type].keys():
            raise DuplicateRegistrationError("Observable Extension", ext_type)
        EXT_MAP[observable_type][ext_type] = new_extension
    except KeyError:
        if observable_type not in OBJ_MAP_OBSERVABLE:
            raise ValueError(
                "Unknown observable type '%s'. Custom observables "
                "must be created with the @CustomObservable decorator."
                % observable_type,
            )
        else:
            EXT_MAP[observable_type] = {ext_type: new_extension}
