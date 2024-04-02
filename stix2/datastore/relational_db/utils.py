from collections.abc import Iterable, Mapping

import inflection

from stix2.v21.base import (
    _DomainObject, _Extension, _MetaObject, _Observable, _RelationshipObject,
)

# Helps us know which data goes in core, and which in a type-specific table.
SCO_COMMON_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged",
}

# Helps us know which data goes in core, and which in a type-specific table.
SDO_COMMON_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged",
    "created",
    "modified",
    "created_by_ref",
    "revoked",
    "labels",
    "confidence",
    "lang",
    "external_references",
}


def canonicalize_table_name(table_name, schema_name=None):
    if schema_name:
        full_name = schema_name + "." + table_name
    else:
        full_name = table_name
    full_name = full_name.replace("-", "_")
    return inflection.underscore(full_name)


def _get_all_subclasses(cls):
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(_get_all_subclasses(subclass))
    return all_subclasses


def get_stix_object_classes():
    yield from _get_all_subclasses(_DomainObject)
    yield from _get_all_subclasses(_RelationshipObject)
    yield from _get_all_subclasses(_Observable)
    yield from _get_all_subclasses(_MetaObject)
    # Non-object extensions (property or toplevel-property only)
    for ext_cls in _get_all_subclasses(_Extension):
        if ext_cls.extension_type not in (
            "new_sdo", "new_sco", "new_sro",
        ):
            yield ext_cls


def schema_for(stix_class):

    if issubclass(stix_class, _DomainObject):
        schema_name = "sdo"
    elif issubclass(stix_class, _RelationshipObject):
        schema_name = "sro"
    elif issubclass(stix_class, _Observable):
        schema_name = "sco"
    elif issubclass(stix_class, _MetaObject):
        schema_name = "common"
    elif issubclass(stix_class, _Extension):
        schema_name = getattr(stix_class, "_applies_to", "sco")
    else:
        schema_name = None

    return schema_name


def table_name_for(stix_type_or_class):
    if isinstance(stix_type_or_class, str):
        table_name = stix_type_or_class
    else:
        # A _STIXBase subclass
        table_name = getattr(stix_type_or_class, "_type", stix_type_or_class.__name__)

    # Applies to registered extension-definition style extensions only.
    # Their "_type" attribute is actually set to the extension definition ID,
    # rather than a STIX type.
    if table_name.startswith("extension-definition"):
        table_name = table_name[0:30]

    table_name = canonicalize_table_name(table_name)
    return table_name


def flat_classes(class_or_classes):
    if isinstance(class_or_classes, Iterable) and not isinstance(
        # Try to generically detect STIX objects, which are iterable, but we
        # don't want to iterate through those.
        class_or_classes, Mapping,
    ):
        for class_ in class_or_classes:
            yield from flat_classes(class_)
    else:
        yield class_or_classes
