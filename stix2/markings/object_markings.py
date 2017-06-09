
import six

from stix2.markings import utils


def get_markings(obj):
    """
    Get all object level markings from the given TLO object.

    Args:
        obj: A TLO object.

    Returns:
        list: Marking IDs contained in the TLO.

    """
    object_markings = obj.get("object_marking_refs", [])

    if not object_markings:
        return []
    elif isinstance(object_markings, six.string_types):
        return [object_markings]
    else:
        return object_markings


def add_markings(obj, marking):
    """
    Appends an object level marking to the object_marking_refs collection.

    Args:
        obj: A TLO object.
        marking: identifier or list of marking identifiers that apply to the
            TLO object.

    Raises:
        AssertionError: If `marking` fail data validation.

    """
    marking = utils.convert_to_list(marking)
    utils.validate(obj, marking=marking)

    if not obj.get("object_marking_refs"):
        obj["object_marking_refs"] = list()

    object_markings = set(obj.get("object_marking_refs") + marking)

    obj["object_marking_refs"] = list(object_markings)


def remove_markings(obj, marking):
    """
    Removes object level marking from the object_marking_refs collection.

    Args:
        obj: A TLO object.
        marking: identifier or list of marking identifiers that apply to the
            TLO object.

    Raises:
        AssertionError: If `marking` fail data validation. Also
            if markings to remove are not found on the provided TLO.

    """
    marking = utils.convert_to_list(marking)
    utils.validate(obj, marking=marking)

    object_markings = obj.get("object_marking_refs", [])

    if not object_markings:
        return []

    if any(x not in obj["object_marking_refs"] for x in marking):
        raise AssertionError("Unable to remove Object Level Marking(s) from "
                             "internal collection. Marking(s) not found...")

    obj["object_marking_refs"] = [x for x in object_markings
                                  if x not in marking]

    if not obj.get("object_marking_refs"):
        obj.pop("object_marking_refs")


def set_markings(obj, marking):
    """
    Removes all object level markings and appends new object level markings to
    the collection. Refer to `clear_markings` and `add_markings` for details.

    Args:
        obj: A TLO object.
        marking: identifier or list of marking identifiers that apply to the
            TLO object.

    """
    utils.validate(obj, marking=marking)

    clear_markings(obj)
    add_markings(obj, marking)


def clear_markings(obj):
    """
    Removes all object level markings from the object_marking_refs collection.

    Args:
        obj: A TLO object.

    """
    try:
        del obj["object_marking_refs"]
    except KeyError:
        raise AssertionError("Unable to clear Object Marking(s) from internal"
                             " collection. No Markings in object...")


def is_marked(obj, marking=None):
    """
    Checks if TLO is marked by any marking or by specific marking(s).

    Args:
        obj: A TLO object.
        marking: identifier or list of marking identifiers that apply to the
            TLO object.

    Returns:
        bool: True if TLO has object level markings. False otherwise.

    Note:
        When a list of marking IDs is provided, if ANY of the provided marking
        IDs matches, True is returned.

    """
    marking = utils.convert_to_list(marking)
    object_markings = obj.get("object_marking_refs", [])

    if marking:
        return any(x in object_markings for x in marking)
    else:
        return bool(object_markings)
