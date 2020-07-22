"""STIX2 core serialization methods."""

import copy
import datetime as dt

import simplejson as json

import stix2.base

from .utils import find_property_index, format_datetime


class STIXJSONEncoder(json.JSONEncoder):
    """Custom JSONEncoder subclass for serializing Python ``stix2`` objects.

    If an optional property with a default value specified in the STIX 2 spec
    is set to that default value, it will be left out of the serialized output.

    An example of this type of property include the ``revoked`` common property.
    """

    def default(self, obj):
        if isinstance(obj, (dt.date, dt.datetime)):
            return format_datetime(obj)
        elif isinstance(obj, stix2.base._STIXBase):
            tmp_obj = dict(copy.deepcopy(obj))
            for prop_name in obj._defaulted_optional_properties:
                del tmp_obj[prop_name]
            return tmp_obj
        else:
            return super(STIXJSONEncoder, self).default(obj)


class STIXJSONIncludeOptionalDefaultsEncoder(json.JSONEncoder):
    """Custom JSONEncoder subclass for serializing Python ``stix2`` objects.

    Differs from ``STIXJSONEncoder`` in that if an optional property with a default
    value specified in the STIX 2 spec is set to that default value, it will be
    included in the serialized output.
    """

    def default(self, obj):
        if isinstance(obj, (dt.date, dt.datetime)):
            return format_datetime(obj)
        elif isinstance(obj, stix2.base._STIXBase):
            return dict(obj)
        else:
            return super(STIXJSONIncludeOptionalDefaultsEncoder, self).default(obj)


def serialize(obj, pretty=False, include_optional_defaults=False, **kwargs):
    """
    Serialize a STIX object.

    Args:
        obj: The STIX object to be serialized.
        pretty (bool): If True, output properties following the STIX specs
            formatting. This includes indentation. Refer to notes for more
            details. (Default: ``False``)
        include_optional_defaults (bool): Determines whether to include
            optional properties set to the default value defined in the spec.
        **kwargs: The arguments for a json.dumps() call.

    Returns:
        str: The serialized JSON object.

    Note:
        The argument ``pretty=True`` will output the STIX object following
        spec order. Using this argument greatly impacts object serialization
        performance. If your use case is centered across machine-to-machine
        operation it is recommended to set ``pretty=False``.

        When ``pretty=True`` the following key-value pairs will be added or
        overridden: indent=4, separators=(",", ": "), item_sort_key=sort_by.
    """
    if pretty:
        def sort_by(element):
            return find_property_index(obj, *element)

        kwargs.update({'indent': 4, 'separators': (',', ': '), 'item_sort_key': sort_by})

    if include_optional_defaults:
        return json.dumps(obj, cls=STIXJSONIncludeOptionalDefaultsEncoder, **kwargs)
    else:
        return json.dumps(obj, cls=STIXJSONEncoder, **kwargs)
