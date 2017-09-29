"""
Filters for Python STIX 2.0 DataSources, DataSinks, DataStores

Classes:
    Filter

"""

import collections
import types

# Currently, only STIX 2.0 common SDO fields (that are not complex objects)
# are supported for filtering on

"""Supported STIX properties"""
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
    "type"
]

"""Supported filter operations"""
FILTER_OPS = ['=', '!=', 'in', '>', '<', '>=', '<=']

"""Supported filter value types"""
FILTER_VALUE_TYPES = [bool, dict, float, int, list, str, tuple]

# filter lookup map - STIX 2 common fields -> filter method
STIX_COMMON_FILTERS_MAP = {}


def _check_filter_components(field, op, value):
        """check filter meets minimum validity

        Note: Currently can create Filters that are not valid
        STIX2 object common properties, as filter.field value
        is not checked, only filter.op, filter.value are checked
        here. They are just ignored when
        applied within the DataSource API. For example, a user
        can add a TAXII Filter, that is extracted and sent to
        a TAXII endpoint within TAXIICollection and not applied
        locally (within this API).
        """

        if op not in FILTER_OPS:
            # check filter operator is supported
            raise ValueError("Filter operator '%s' not supported for specified field: '%s'" % (op, field))

        if type(value) not in FILTER_VALUE_TYPES:
            # check filter value type is supported
            raise TypeError("Filter value type '%s' is not supported. The type must be a python immutable type or dictionary" % type(value))

        return True


class Filter(collections.namedtuple("Filter", ['field', 'op', 'value'])):
    """STIX 2 filters that support the querying functionality of STIX 2
    DataStores and DataSources.

    Initialized like a python tuple

    Args:
        field (str): filter field name, corresponds to STIX 2 object property

        op (str): operator of the filter

        value (str): filter field value

    Example:
        Filter("id", "=", "malware--0f862b01-99da-47cc-9bdb-db4a86a95bb1")

    """
    __slots__ = ()

    def __new__(cls, field, op, value):
        # If value is a list, convert it to a tuple so it is hashable.
        if isinstance(value, list):
            value = tuple(value)

        _check_filter_components(field, op, value)

        self = super(Filter, cls).__new__(cls, field, op, value)
        return self

    @property
    def common(self):
        """return whether Filter is valid STIX2 Object common property

        Note: The Filter operator and Filter value type are checked when
        the filter is created, thus only leaving the Filter field to be
        checked to make sure a valid STIX2 Object common property.

        Note: Filters that are not valid STIX2 Object common property
        Filters are still allowed to be created for extended usage of
        Filter. (e.g. TAXII specific filters can be created, which are
        then extracted and sent to TAXII endpoint.)
        """
        return self.field in STIX_COMMON_FIELDS


def apply_common_filters(stix_objs, query):
    """Evaluate filters against a set of STIX 2.0 objects.

    Supports only STIX 2.0 common property fields

    Args:
        stix_objs (list): list of STIX objects to apply the query to
        query (set): set of filters (combined form complete query)

    Returns:
        (generator): of STIX objects that successfully evaluate against
            the query.

    """
    for stix_obj in stix_objs:
        clean = True
        for filter_ in query:
            if not filter_.common:
                # skip filter as it is not a STIX2 Object common property filter
                continue

            if "." in filter_.field:
                # For properties like granular_markings and external_references
                # need to extract the first property from the string.
                field = filter_.field.split(".")[0]
            else:
                field = filter_.field

            if field not in stix_obj.keys():
                # check filter "field" is in STIX object - if cant be
                # applied to STIX object, STIX object is discarded
                # (i.e. did not make it through the filter)
                clean = False
                break

            match = STIX_COMMON_FILTERS_MAP[filter_.field.split('.')[0]](filter_, stix_obj)

            if not match:
                clean = False
                break
            elif match == -1:
                raise ValueError("Error, filter operator: {0} not supported for specified field: {1}".format(filter_.op, filter_.field))

        # if object unmarked after all filters, add it
        if clean:
            yield stix_obj


"""Base type filters"""


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
    """base STIX id filter"""
    if filter_.op == "=":
        return stix_obj_id == filter_.value
    elif filter_.op == "!=":
        return stix_obj_id != filter_.value
    else:
        return -1


def _boolean_filter(filter_, stix_obj_field):
    """base boolean filter"""
    if filter_.op == "=":
        return stix_obj_field == filter_.value
    elif filter_.op == "!=":
        return stix_obj_field != filter_.value
    else:
        return -1


def _string_filter(filter_, stix_obj_field):
    """base string filter"""
    return _all_filter(filter_, stix_obj_field)


def _timestamp_filter(filter_, stix_obj_timestamp):
    """base STIX 2 timestamp filter"""
    return _all_filter(filter_, stix_obj_timestamp)


"""STIX 2.0 Common Property Filters

The naming of these functions is important as
they are used to index a mapping dictionary from
STIX common field names to these filter functions.

REQUIRED naming scheme:
    "check_<STIX field name>_filter"

"""


def check_created_filter(filter_, stix_obj):
    return _timestamp_filter(filter_, stix_obj["created"])


def check_created_by_ref_filter(filter_, stix_obj):
    return _id_filter(filter_, stix_obj["created_by_ref"])


def check_external_references_filter(filter_, stix_obj):
    """
    STIX object's can have a list of external references

    external_references properties supported:
        external_references.source_name (string)
        external_references.description (string)
        external_references.url (string)
        external_references.external_id  (string)

    external_references properties not supported:
        external_references.hashes

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
