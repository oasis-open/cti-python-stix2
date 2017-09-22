"""
Filters for Python STIX 2.0 DataSources, DataSinks, DataStores

Classes:
    Filter

TODO:
    The script at the bottom of the module works (to capture
    all the callable filter methods), however it causes this module
    to be imported by itself twice. Not sure how big of deal that is,
    or if cleaner solution possible.
"""

import collections
import types

# Currently, only STIX 2.0 common SDO fields (that are not complex objects)
# are supported for filtering on
STIX_COMMON_FIELDS = [
    "created",
    "created_by_ref",
    "external_references.source_name",
    "external_references.description",
    "external_references.url",
    "external_references.hashes",
    "external_references.external_id",
    "granular_markings.marking_ref",
    "granular_markings.selectors",
    "id",
    "labels",
    "modified",
    "object_marking_refs",
    "revoked",
    "type",
    "granular_markings"
]

# Supported filter operations
FILTER_OPS = ['=', '!=', 'in', '>', '<', '>=', '<=']

# Supported filter value types
FILTER_VALUE_TYPES = [bool, dict, float, int, list, str, tuple]

# filter lookup map - STIX 2 common fields -> filter method
STIX_COMMON_FILTERS_MAP = {}


class Filter(collections.namedtuple("Filter", ['field', 'op', 'value'])):
    __slots__ = ()

    def __new__(cls, field, op, value):
        # If value is a list, convert it to a tuple so it is hashable.
        if isinstance(value, list):
            value = tuple(value)
        self = super(Filter, cls).__new__(cls, field, op, value)
        return self


# primitive type filters

def _all_filter(filter_, stix_obj_field):
    """all filter operations (for filters whose value type can be applied to any operation type)"""
    if filter_.op == "=":
        return stix_obj_field == filter_.value
    elif filter_.op == "!=":
        return stix_obj_field != filter_.value
    elif filter_.op == "in":
        return stix_obj_field in filter_.value
    elif filter_.op == ">":
        return stix_obj_field > filter_.value
    elif filter_.op == "<":
        return stix_obj_field < filter_.value
    elif filter_.op == ">=":
        return stix_obj_field >= filter_.value
    elif filter_.op == "<=":
        return stix_obj_field <= filter_.value
    else:
        return -1


def _id_filter(filter_, stix_obj_id):
    """base filter types"""
    if filter_.op == "=":
        return stix_obj_id == filter_.value
    elif filter_.op == "!=":
        return stix_obj_id != filter_.value
    else:
        return -1


def _boolean_filter(filter_, stix_obj_field):
    if filter_.op == "=":
        return stix_obj_field == filter_.value
    elif filter_.op == "!=":
        return stix_obj_field != filter_.value
    else:
        return -1


def _string_filter(filter_, stix_obj_field):
    return _all_filter(filter_, stix_obj_field)


def _timestamp_filter(filter_, stix_obj_timestamp):
    return _all_filter(filter_, stix_obj_timestamp)

# STIX 2.0 Common Property filters
# The naming of these functions is important as
# they are used to index a mapping dictionary from
# STIX common field names to these filter functions.
#
# REQUIRED naming scheme:
# "check_<STIX field name>_filter"


def check_created_filter(filter_, stix_obj):
    return _timestamp_filter(filter_, stix_obj["created"])


def check_created_by_ref_filter(filter_, stix_obj):
    return _id_filter(filter_, stix_obj["created_by_ref"])


def check_external_references_filter(filter_, stix_obj):
    """
    STIX object's can have a list of external references

    external_references properties:
        external_references.source_name (string)
        external_references.description (string)
        external_references.url (string)
        external_references.hashes (hash, but for filtering purposes, a string)
        external_references.external_id  (string)

    """
    for er in stix_obj["external_references"]:
        # grab er property name from filter field
        filter_field = filter_.field.split(".")[1]
        r = _string_filter(filter_, er[filter_field])
        if r:
            return r
    return False


def check_granular_markings_filter(filter_, stix_obj):
    """
    STIX object's can have a list of granular marking references

    granular_markings properties:
        granular_markings.marking_ref (id)
        granular_markings.selectors  (string)

    """
    for gm in stix_obj["granular_markings"]:
        # grab gm property name from filter field
        filter_field = filter_.field.split(".")[1]

        if filter_field == "marking_ref":
            return _id_filter(filter_, gm[filter_field])

        elif filter_field == "selectors":
            for selector in gm[filter_field]:
                r = _string_filter(filter_, selector)
                if r:
                    return r
    return False


def check_id_filter(filter_, stix_obj):
    return _id_filter(filter_, stix_obj["id"])


def check_labels_filter(filter_, stix_obj):
    for label in stix_obj["labels"]:
        r = _string_filter(filter_, label)
        if r:
            return r
    return False


def check_modified_filter(filter_, stix_obj):
    return _timestamp_filter(filter_, stix_obj["modified"])


def check_object_marking_refs_filter(filter_, stix_obj):
    for marking_id in stix_obj["object_marking_refs"]:
        r = _id_filter(filter_, marking_id)
        if r:
            return r
    return False


def check_revoked_filter(filter_, stix_obj):
    return _boolean_filter(filter_, stix_obj["revoked"])


def check_type_filter(filter_, stix_obj):
    return _string_filter(filter_, stix_obj["type"])


# Create mapping of field names to filter functions
for name, obj in dict(globals()).items():
    if "check_" in name and isinstance(obj, types.FunctionType):
        field_name = "_".join(name.split("_")[1:-1])
        STIX_COMMON_FILTERS_MAP[field_name] = obj
