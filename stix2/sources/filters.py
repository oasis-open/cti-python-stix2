"""
Filters for Python STIX 2.0 DataSources, DataSinks, DataStores

"""

import collections

"""Supported filter operations"""
FILTER_OPS = ['=', '!=', 'in', '>', '<', '>=', '<=']

"""Supported filter value types"""
FILTER_VALUE_TYPES = [bool, dict, float, int, list, str, tuple]
try:
    FILTER_VALUE_TYPES.append(unicode)
except NameError:
    # Python 3 doesn't need to worry about unicode
    pass


def _check_filter_components(prop, op, value):
    """Check that filter meets minimum validity.

    Note:
        Currently can create Filters that are not valid STIX2 object common
        properties, as filter.prop value is not checked, only filter.op,
        filter value are checked here. They are just ignored when applied
        within the DataSource API. For example, a user can add a TAXII Filter,
        that is extracted and sent to a TAXII endpoint within TAXIICollection
        and not applied locally (within this API).

    """
    if op not in FILTER_OPS:
        # check filter operator is supported
        raise ValueError("Filter operator '%s' not supported for specified property: '%s'" % (op, prop))

    if type(value) not in FILTER_VALUE_TYPES:
        # check filter value type is supported
        raise TypeError("Filter value type '%s' is not supported. The type must be a Python immutable type or dictionary" % type(value))

    return True


class Filter(collections.namedtuple("Filter", ['property', 'op', 'value'])):
    """STIX 2 filters that support the querying functionality of STIX 2
    DataStores and DataSources.

    Initialized like a Python tuple.

    Args:
        property (str): filter property name, corresponds to STIX 2 object property
        op (str): operator of the filter
        value (str): filter property value

    Example:
        Filter("id", "=", "malware--0f862b01-99da-47cc-9bdb-db4a86a95bb1")

    """
    __slots__ = ()

    def __new__(cls, prop, op, value):
        # If value is a list, convert it to a tuple so it is hashable.
        if isinstance(value, list):
            value = tuple(value)

        _check_filter_components(prop, op, value)

        self = super(Filter, cls).__new__(cls, prop, op, value)
        return self

    def _check_property(self, stix_obj_property):
        """Check a property of a STIX Object against this filter.

        Args:
            stix_obj_property: value to check this filter against

        Returns:
            True if property matches the filter,
            False otherwise.
        """
        if self.op == "=":
            return stix_obj_property == self.value
        elif self.op == "!=":
            return stix_obj_property != self.value
        elif self.op == "in":
            return stix_obj_property in self.value
        elif self.op == ">":
            return stix_obj_property > self.value
        elif self.op == "<":
            return stix_obj_property < self.value
        elif self.op == ">=":
            return stix_obj_property >= self.value
        elif self.op == "<=":
            return stix_obj_property <= self.value
        else:
            raise ValueError("Filter operator: {0} not supported for specified property: {1}".format(self.op, self.property))


def apply_common_filters(stix_objs, query):
    """Evaluate filters against a set of STIX 2.0 objects.

    Supports only STIX 2.0 common property properties.

    Args:
        stix_objs (list): list of STIX objects to apply the query to
        query (set): set of filters (combined form complete query)

    Yields:
        STIX objects that successfully evaluate against the query.

    """
    for stix_obj in stix_objs:
        clean = True
        for filter_ in query:
            match = _check_filter(filter_, stix_obj)

            if not match:
                clean = False
                break

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
    # For properties like granular_markings and external_references
    # need to extract the first property from the string.
    prop = filter_.property.split(".")[0]

    if prop not in stix_obj.keys():
        # check filter "property" is in STIX object - if cant be
        # applied to STIX object, STIX object is discarded
        # (i.e. did not make it through the filter)
        return False

    if "." in filter_.property:
        # Check embedded properties, from e.g. granular_markings or external_references
        sub_property = filter_.property.split(".", 1)[1]
        sub_filter = filter_._replace(property=sub_property)
        if isinstance(stix_obj[prop], list):
            for elem in stix_obj[prop]:
                if _check_filter(sub_filter, elem) is True:
                    return True
            return False
        else:
            return _check_filter(sub_filter, stix_obj[prop])
    elif isinstance(stix_obj[prop], list):
        # Check each item in list property to see if it matches
        for elem in stix_obj[prop]:
            if filter_._check_property(elem) is True:
                return True
        return False
    else:
        # Check if property matches
        return filter_._check_property(stix_obj[prop])
