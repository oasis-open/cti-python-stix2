"""
Filters for Python STIX 2.0 DataSources, DataSinks, DataStores

"""

import collections

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


def _check_filter_components(field, op, value):
        """Check that filter meets minimum validity.

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
            raise TypeError("Filter value type '%s' is not supported. The type must be a Python immutable type or dictionary" % type(value))

        return True


class Filter(collections.namedtuple("Filter", ['field', 'op', 'value'])):
    """STIX 2 filters that support the querying functionality of STIX 2
    DataStores and DataSources.

    Initialized like a Python tuple.

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


def apply_common_filters(stix_objs, query):
    """Evaluate filters against a set of STIX 2.0 objects.

    Supports only STIX 2.0 common property fields.

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
            match = _check_filter(filter_, stix_obj)

            if not match:
                clean = False
                break
            elif match == -1:
                raise ValueError("Error, filter operator: {0} not supported for specified field: {1}".format(filter_.op, filter_.field))

        # if object unmarked after all filters, add it
        if clean:
            yield stix_obj


def _check_filter(filter_, stix_obj):
    """Evaluate a single filter against a single STIX 2.0 object.

    Args:
        filter_ (Filter): filter to match against
        stix_obj: STIX object to apply the filter to

    Returns:
        True if the stix_obj matches the filter,
        False if not.

    """
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
        return False

    if "." in filter_.field:
        # Check embedded properties, from e.g. granular_markings or external_references
        sub_field = filter_.field.split(".", 1)[1]
        sub_filter = filter_._replace(field=sub_field)
        if isinstance(stix_obj[field], list):
            for elem in stix_obj[field]:
                r = _check_filter(sub_filter, elem)
                if r:
                    return r
            return False
        else:
            return _check_filter(sub_filter, stix_obj[field])
    elif isinstance(stix_obj[field], list):
        # Check each item in list property to see if it matches
        for elem in stix_obj[field]:
            r = _all_filter(filter_, elem)
            if r:
                return r
        return False
    else:
        # Check if property matches
        return _all_filter(filter_, stix_obj[field])


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
