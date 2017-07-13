
from stix2.markings import utils


def get_markings(obj):
    """
    Get all object level markings from the given SDO or SRO object.

    Args:
        obj: A SDO or SRO object.

    Returns:
        list: Marking IDs contained in the SDO or SRO. Empty list if no
            markings are present in `object_marking_refs`.

    """
    return obj.get("object_marking_refs", [])


def add_markings(obj, marking):
    """
    Appends an object level marking to the object_marking_refs collection.

    Args:
        obj: A SDO or SRO object.
        marking: identifier or list of identifiers to apply SDO or SRO object.

    Raises:
        AssertionError: If `marking` fail data validation.

    """
    marking = utils.convert_to_list(marking)

    # TODO: Remove set for comparison and raise DuplicateMarkingException.
    object_markings = set(obj.get("object_marking_refs", []) + marking)

    return obj.new_version(object_marking_refs=list(object_markings))


def remove_markings(obj, marking):
    """
    Removes object level marking from the object_marking_refs collection.

    Args:
        obj: A SDO or SRO object.
        marking: identifier or list of identifiers that apply to the
            SDO or SRO object.

    Raises:
        AssertionError: If markings to remove are not found on the provided
            SDO or SRO.

    """
    marking = utils.convert_to_list(marking)
    utils.validate(obj, marking=marking)

    object_markings = obj.get("object_marking_refs", [])

    if not object_markings:
        return obj

    if any(x not in obj["object_marking_refs"] for x in marking):
        raise AssertionError("Unable to remove Object Level Marking(s) from "
                             "internal collection. Marking(s) not found...")

    return obj.new_version(object_marking_refs=[x for x in object_markings
                                                if x not in marking])


def set_markings(obj, marking):
    """
    Removes all object level markings and appends new object level markings to
    the collection. Refer to `clear_markings` and `add_markings` for details.

    Args:
        obj: A SDO or SRO object.
        marking: identifier or list of identifiers to apply in the
            SDO or SRO object.

    """
    return add_markings(clear_markings(obj), marking)


def clear_markings(obj):
    """
    Removes all object level markings from the object_marking_refs collection.

    Args:
        obj: A SDO or SRO object.

    """
    return obj.new_version(object_marking_refs=None)


def is_marked(obj, marking=None):
    """
    Checks if SDO or SRO is marked by any marking or by specific marking(s).

    Args:
        obj: A SDO or SRO object.
        marking: identifier or list of marking identifiers that apply to the
            SDO or SRO object.

    Returns:
        bool: True if SDO or SRO has object level markings. False otherwise.

    Note:
        When an identifier or list of identifiers is provided, if ANY of the
        provided marking refs match, True is returned.

    """
    marking = utils.convert_to_list(marking)
    object_markings = obj.get("object_marking_refs", [])

    if marking:
        return any(x in object_markings for x in marking)
    else:
        return bool(object_markings)
