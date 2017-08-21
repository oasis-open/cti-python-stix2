"""
Python STIX 2.0 Data Markings API.

These high level functions will operate on both object level markings and
granular markings unless otherwise noted in each of the functions.
"""

from stix2.markings import granular_markings, object_markings


def get_markings(obj, selectors, inherited=False, descendants=False):
    """
    Get all markings associated to the field(s).

    Args:
        obj: A TLO object.
        selectors: string or list of selectors strings relative to the TLO in
            which the field(s) appear(s).
        inherited: If True, include object level markings and granular markings
            inherited relative to the field(s).
        descendants: If True, include granular markings applied to any children
            relative to the field(s).

    Returns:
        list: Marking IDs that matched the selectors expression.

    Note:
        If ``selectors`` is None, operation will be performed only on object
        level markings.

    """
    if selectors is None:
        return object_markings.get_markings(obj)

    results = granular_markings.get_markings(
        obj,
        selectors,
        inherited,
        descendants
    )

    if inherited:
        results.extend(object_markings.get_markings(obj))

    return list(set(results))


def set_markings(obj, selectors, marking):
    """
    Removes all markings associated with selectors and appends a new granular
    marking. Refer to `clear_markings` and `add_markings` for details.

    Args:
        obj: A TLO object.
        selectors: string or list of selectors strings relative to the TLO in
            which the field(s) appear(s).
        marking: identifier or list of marking identifiers that apply to the
            field(s) selected by `selectors`.

    Note:
        If ``selectors`` is None, operations will be performed on object level
        markings. Otherwise on granular markings.

    """
    if selectors is None:
        return object_markings.set_markings(obj, marking)
    else:
        return granular_markings.set_markings(obj, selectors, marking)


def remove_markings(obj, selectors, marking):
    """
    Removes granular_marking from the granular_markings collection.

    Args:
        obj: A TLO object.
        selectors: string or list of selectors strings relative to the TLO in
            which the field(s) appear(s).
        marking: identifier or list of marking identifiers that apply to the
            field(s) selected by `selectors`.

    Raises:
        AssertionError: If `selectors` or `marking` fail data validation. Also
            if markings to remove are not found on the provided TLO.

    Note:
        If ``selectors`` is None, operations will be performed on object level
        markings. Otherwise on granular markings.

   """
    if selectors is None:
        return object_markings.remove_markings(obj, marking)
    else:
        return granular_markings.remove_markings(obj, selectors, marking)


def add_markings(obj, selectors, marking):
    """
    Appends a granular_marking to the granular_markings collection.

    Args:
        obj: A TLO object.
        selectors: string or list of selectors strings relative to the TLO in
            which the field(s) appear(s).
        marking: identifier or list of marking identifiers that apply to the
            field(s) selected by `selectors`.

    Raises:
        AssertionError: If `selectors` or `marking` fail data validation.

    Note:
        If ``selectors`` is None, operations will be performed on object level
        markings. Otherwise on granular markings.

    """
    if selectors is None:
        return object_markings.add_markings(obj, marking)
    else:
        return granular_markings.add_markings(obj, selectors, marking)


def clear_markings(obj, selectors):
    """
    Removes all granular_marking associated with the selectors.

    Args:
        obj: A TLO object.
        selectors: string or list of selectors strings relative to the TLO in
            which the field(s) appear(s).

    Note:
        If ``selectors`` is None, operations will be performed on object level
        markings. Otherwise on granular markings.

    """
    if selectors is None:
        return object_markings.clear_markings(obj)
    else:
        return granular_markings.clear_markings(obj, selectors)


def is_marked(obj, selectors, marking=None, inherited=False, descendants=False):
    """
    Checks if field(s) is marked by any marking or by specific marking(s).

    Args:
        obj: A TLO object.
        selectors: string or list of selectors strings relative to the TLO in
            which the field(s) appear(s).
        marking: identifier or list of marking identifiers that apply to the
            field(s) selected by `selectors`.
        inherited: If True, include object level markings and granular markings
            inherited to determine if the field(s) is/are marked.
        descendants: If True, include granular markings applied to any children
            of the given selector to determine if the field(s) is/are marked.

    Returns:
        bool: True if ``selectors`` is found on internal TLO collection.
            False otherwise.

    Note:
        When a list of marking IDs is provided, if ANY of the provided marking
        IDs matches, True is returned.

        If ``selectors`` is None, operation will be performed only on object
        level markings.

    """
    if selectors is None:
        return object_markings.is_marked(obj, marking)

    result = granular_markings.is_marked(
        obj,
        selectors,
        marking,
        inherited,
        descendants
    )

    if inherited:
        granular_marks = granular_markings.get_markings(obj, selectors)
        object_marks = object_markings.get_markings(obj)

        if granular_marks:
            result = granular_markings.is_marked(
                obj,
                selectors,
                granular_marks,
                inherited,
                descendants
            )

        result = result or object_markings.is_marked(obj, object_marks)

    return result
