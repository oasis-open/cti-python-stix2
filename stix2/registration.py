import itertools
import re

from . import registry, version
from .base import _DomainObject
from .exceptions import DuplicateRegistrationError
from .properties import _validate_type
from .utils import PREFIX_21_REGEX, get_class_hierarchy_names


def _register_object(new_type, version=version.DEFAULT_VERSION):
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

    if not version:
        version = version.DEFAULT_VERSION

    if version == "2.1":
        for prop_name, prop in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character" % prop_name)

    OBJ_MAP = registry.STIX2_OBJ_MAPS[version]['objects']
    if new_type._type in OBJ_MAP.keys():
        raise DuplicateRegistrationError("STIX Object", new_type._type)
    OBJ_MAP[new_type._type] = new_type


def _register_marking(new_marking, version=version.DEFAULT_VERSION):
    """Register a custom STIX Marking Definition type.

    Args:
        new_marking (class): A class to register in the Marking map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """

    mark_type = new_marking._type
    properties = new_marking._properties

    if not version:
        version = version.DEFAULT_VERSION

    _validate_type(mark_type, version)

    if version == "2.1":
        for prop_name, prop_value in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)

    OBJ_MAP_MARKING = registry.STIX2_OBJ_MAPS[version]['markings']
    if mark_type in OBJ_MAP_MARKING.keys():
        raise DuplicateRegistrationError("STIX Marking", mark_type)
    OBJ_MAP_MARKING[mark_type] = new_marking


def _register_observable(new_observable, version=version.DEFAULT_VERSION):
    """Register a custom STIX Cyber Observable type.

    Args:
        new_observable (class): A class to register in the Observables map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    properties = new_observable._properties

    if not version:
        version = version.DEFAULT_VERSION

    if version == "2.0":
        # If using STIX2.0, check properties ending in "_ref/s" are ObjectReferenceProperties
        for prop_name, prop in properties.items():
            if prop_name.endswith('_ref') and ('ObjectReferenceProperty' not in get_class_hierarchy_names(prop)):
                raise ValueError(
                    "'%s' is named like an object reference property but "
                    "is not an ObjectReferenceProperty." % prop_name,
                )
            elif (
                prop_name.endswith('_refs') and (
                    'ListProperty' not in get_class_hierarchy_names(prop) or
                    'ObjectReferenceProperty' not in get_class_hierarchy_names(prop.contained)
                )
            ):
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
            elif (
                prop_name.endswith('_refs') and (
                    'ListProperty' not in get_class_hierarchy_names(prop) or
                    'ReferenceProperty' not in get_class_hierarchy_names(prop.contained)
                )
            ):
                raise ValueError(
                    "'%s' is named like a reference list property but "
                    "is not a ListProperty containing ReferenceProperty." % prop_name,
                )

    OBJ_MAP_OBSERVABLE = registry.STIX2_OBJ_MAPS[version]['observables']
    if new_observable._type in OBJ_MAP_OBSERVABLE.keys():
        raise DuplicateRegistrationError("Cyber Observable", new_observable._type)
    OBJ_MAP_OBSERVABLE[new_observable._type] = new_observable


def _register_extension(
    new_extension, version=version.DEFAULT_VERSION,
):
    """Register a custom extension to any STIX Object type.

    Args:
        new_extension (class): A class to register in the Extensions map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1").
            Defaults to the latest supported version.

    """
    ext_type = new_extension._type

    # Need to check both toplevel and nested properties
    prop_groups = [new_extension._properties]
    if hasattr(new_extension, "_toplevel_properties"):
        prop_groups.append(new_extension._toplevel_properties)
    prop_names = itertools.chain.from_iterable(prop_groups)

    _validate_type(ext_type, version)

    if not new_extension._properties:
        raise ValueError(
            "Invalid extension: must define at least one property: " +
            ext_type,
        )

    if version == "2.1":
        if not (ext_type.endswith('-ext') or ext_type.startswith('extension-definition--')):
            raise ValueError(
                "Invalid extension type name '%s': must end with '-ext' or start with 'extension-definition--<UUID>'." %
                ext_type,
            )

        for prop_name in prop_names:
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)

    EXT_MAP = registry.STIX2_OBJ_MAPS[version]['extensions']

    if ext_type in EXT_MAP:
        raise DuplicateRegistrationError("Extension", ext_type)
    EXT_MAP[ext_type] = new_extension
