
import collections

import six


def evaluate_expression(obj, selector):

    for items, value in iterpath(obj):
        path = ".".join(items)

        if path == selector and value:
            return [value]

    return []


def validate_selector(obj, selector):
    results = list(evaluate_expression(obj, selector))

    if len(results) >= 1:
        return True


def validate_markings(marking):
    if isinstance(marking, six.string_types):
        if not marking:
            return False
        else:
            return True

    elif isinstance(marking, list) and len(marking) >= 1:
        for m in marking:
            if not m:
                return False
            elif not isinstance(m, six.string_types):
                return False

        return True
    else:
        return False


def validate(obj, selectors=None, marking=None):

    if selectors is not None:
        assert selectors

        for s in selectors:
            assert validate_selector(obj, s)

    if marking is not None:
        assert validate_markings(marking)


def convert_to_list(data):
    if data is not None:
        if isinstance(data, list):
            return data
        else:
            return [data]


def fix_value(data):
    data = convert_to_list(data)

    return data


def compress_markings(granular_markings):

    if not granular_markings:
        return

    map_ = collections.defaultdict(set)

    for granular_marking in granular_markings:
        if granular_marking.get("marking_ref"):
            map_[granular_marking.get("marking_ref")].update(granular_marking.get("selectors"))

    compressed = \
        [
            {"marking_ref": marking_ref, "selectors": sorted(selectors)}
            for marking_ref, selectors in six.iteritems(map_)
        ]

    return compressed


def expand_markings(granular_markings):

    if not granular_markings:
        return

    expanded = []

    for marking in granular_markings:
        selectors = marking.get("selectors")
        marking_ref = marking.get("marking_ref")

        expanded.extend(
            [
                {"marking_ref": marking_ref, "selectors": [selector]}
                for selector in selectors
            ]
        )

    return expanded


def build_granular_marking(granular_marking):
    tlo = {"granular_markings": granular_marking}

    expand_markings(tlo["granular_markings"])

    return tlo


def iterpath(obj, path=None):
    """
    Generator which walks the input ``obj`` model. Each iteration yields a
    tuple containing a list of ancestors and the property value.

    Args:
        obj: A TLO object.
        path: None, used recursively to store ancestors.

    Example:
        >>> for item in iterpath(obj):
        >>>     print(item)
        (['type'], 'campaign')
        ...
        (['cybox', 'objects', '[0]', 'hashes', 'sha1'], 'cac35ec206d868b7d7cb0b55f31d9425b075082b')

    Returns:
        tuple: Containing two items: a list of ancestors and the
            property value.

    """
    if path is None:
        path = []

    for varname, varobj in iter(sorted(six.iteritems(obj))):
        path.append(varname)
        yield (path, varobj)

        if isinstance(varobj, dict):

            for item in iterpath(varobj, path):
                yield item

        elif isinstance(varobj, list):

            for item in varobj:
                index = "[{0}]".format(varobj.index(item))
                path.append(index)

                yield (path, item)

                if isinstance(item, dict):
                    for descendant in iterpath(item, path):
                        yield descendant

                path.pop()

        path.pop()


def get_selector(obj, prop):
    """
    Function that creates a selector based on ``prop``.

    Args:
        obj: A TLO object.
        prop: A property of the TLO object.

    Note:
        Must supply the actual value inside the structure. Since some
        limitations exist with Python interning methods, checking for object
        location is for now the option to assert the data.

    Example:
        >>> selector = get_selector(obj, obj["cybox"]["objects"][0]["file_name"])
        >>> print(selector)
        ["cybox.objects.[0].file_name"]

    Returns:
        list: A list with one selector that asserts the supplied property.
            Empty list if it was unable to find the property.

    """
    selector = []

    for ancestors, value in iterpath(obj):
        if value is prop:
            path = ".".join(ancestors)
            selector.append(path)

    return selector
