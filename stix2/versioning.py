"""STIX2 core versioning methods."""

import copy
import datetime as dt
import itertools
import uuid

import six
from six.moves.collections_abc import Mapping

import stix2.base
from stix2.utils import get_timestamp, parse_into_datetime
import stix2.v20

from .exceptions import (
    InvalidValueError, RevokeError, UnmodifiablePropertyError,
)

# STIX object properties that cannot be modified
STIX_UNMOD_PROPERTIES = ['created', 'created_by_ref', 'id', 'type']
_VERSIONING_PROPERTIES = {"created", "modified", "revoked"}


def _fudge_modified(old_modified, new_modified, use_stix21):
    """
    Ensures a new modified timestamp is newer than the old.  When they are
    too close together, new_modified must be pushed further ahead to ensure
    it is distinct and later, after JSON serialization (which may mean it's
    actually being pushed a little ways into the future).  JSON serialization
    can remove precision, which can cause distinct timestamps to accidentally
    become equal, if we're not careful.

    :param old_modified: A previous "modified" timestamp, as a datetime object
    :param new_modified: A candidate new "modified" timestamp, as a datetime
        object
    :param use_stix21: Whether to use STIX 2.1+ versioning timestamp precision
        rules (boolean).  This is important so that we are aware of how
        timestamp precision will be truncated, so we know how close together
        the timestamps can be, and how far ahead to potentially push the new
        one.
    :return: A suitable new "modified" timestamp.  This may be different from
        what was passed in, if it had to be pushed ahead.
    """
    if use_stix21:
        # 2.1+: we can use full precision
        if new_modified <= old_modified:
            new_modified = old_modified + dt.timedelta(microseconds=1)
    else:
        # 2.0: we must use millisecond precision
        one_ms = dt.timedelta(milliseconds=1)
        if new_modified - old_modified < one_ms:
            new_modified = old_modified + one_ms

    return new_modified


def _is_versionable(data):
    """
    Determine whether the given object is versionable.  This check is done on
    the basis of support for three properties for the object type: "created",
    "modified", and "revoked".  If all three are supported, the object is
    versionable; otherwise it is not.  Dicts must have a "type" property whose
    value is for a registered object type.  This is used to determine a
    complete set of supported properties for the type.

    Also, detect whether it represents a STIX 2.1 or greater spec version.

    :param data: The object to check.  Must be either a stix object, or a dict
        with a "type" property.
    :return: A 2-tuple of bools: the first is True if the object is versionable
        and False if not; the second is True if the object is STIX 2.1+ and
        False if not.
    """

    is_versionable = False
    is_21 = False
    stix_vid = None

    if isinstance(data, Mapping):

        # First, determine spec version.  It's easy for our stix2 objects; more
        # work for dicts.
        is_21 = False
        if isinstance(data, stix2.base._STIXBase) and \
                not isinstance(data, stix2.v20._STIXBase20):
            # (is_21 means 2.1 or later; try not to be 2.1-specific)
            is_21 = True
        elif isinstance(data, dict):
            stix_vid = stix2.parsing._detect_spec_version(data)
            is_21 = stix_vid != "v20"

        # Then, determine versionability.

        if six.PY2:
            # dumb python2 compatibility: map.keys() returns a list, not a set!
            # six.viewkeys() compatibility function uses dict.viewkeys() on
            # python2, which is not a Mapping mixin method, so that doesn't
            # work either (for our stix2 objects).
            keys = set(data)
        else:
            keys = data.keys()

        # This should be sufficient for STIX objects; maybe we get lucky with
        # dicts here but probably not.
        if keys >= _VERSIONING_PROPERTIES:
            is_versionable = True

        # Tougher to handle dicts.  We need to consider STIX version, map to a
        # registered class, and from that get a more complete picture of its
        # properties.
        elif isinstance(data, dict):
            class_maps = stix2.parsing.STIX2_OBJ_MAPS[stix_vid]
            obj_type = data["type"]

            if obj_type in class_maps["objects"]:
                # Should we bother checking properties for SDOs/SROs?
                # They were designed to be versionable.
                is_versionable = True

            elif obj_type in class_maps["observables"]:
                # but do check SCOs
                cls = class_maps["observables"][obj_type]
                is_versionable = _VERSIONING_PROPERTIES.issubset(
                    cls._properties,
                )

    return is_versionable, is_21


def new_version(data, allow_custom=None, **kwargs):
    """
    Create a new version of a STIX object, by modifying properties and
    updating the ``modified`` property.

    :param data: The object to create a new version of.  Maybe a stix2 object
        or dict.
    :param allow_custom: Whether to allow custom properties on the new object.
        If True, allow them (regardless of whether the original had custom
        properties); if False disallow them; if None, propagate the preference
        from the original object.
    :param kwargs: The properties to change.  Setting to None requests property
        removal.
    :return: The new object.
    """

    is_versionable, is_21 = _is_versionable(data)

    if not is_versionable:
        raise ValueError(
            "cannot create new version of object of this type! "
            "Try a dictionary or instance of an SDO or SRO class.",
        )

    if data.get('revoked'):
        raise RevokeError("new_version")
    try:
        new_obj_inner = copy.deepcopy(data._inner)
    except AttributeError:
        new_obj_inner = copy.deepcopy(data)

    # Make sure certain properties aren't trying to change
    # ID contributing properties of 2.1+ SCOs may also not change if a UUIDv5
    # is in use (depending on whether they were used to create it... but they
    # probably were).  That would imply an ID change, which is not allowed
    # across versions.
    sco_locked_props = []
    if is_21 and isinstance(data, stix2.base._Observable):
        uuid_ = uuid.UUID(data["id"][-36:])
        if uuid_.variant == uuid.RFC_4122 and uuid_.version == 5:
            sco_locked_props = data._id_contributing_properties

    unchangable_properties = set()
    for prop in itertools.chain(STIX_UNMOD_PROPERTIES, sco_locked_props):
        if prop in kwargs:
            unchangable_properties.add(prop)
    if unchangable_properties:
        raise UnmodifiablePropertyError(unchangable_properties)

    # Different versioning precision rules in STIX 2.0 vs 2.1, so we need
    # to know which rules to apply.
    precision_constraint = "min" if is_21 else "exact"

    cls = type(data)
    if 'modified' not in kwargs:
        old_modified = parse_into_datetime(
            data["modified"], precision="millisecond",
            precision_constraint=precision_constraint,
        )

        new_modified = get_timestamp()
        new_modified = _fudge_modified(old_modified, new_modified, is_21)

        kwargs['modified'] = new_modified

    elif 'modified' in data:
        old_modified_property = parse_into_datetime(
            data.get('modified'), precision='millisecond',
            precision_constraint=precision_constraint,
        )
        new_modified_property = parse_into_datetime(
            kwargs['modified'], precision='millisecond',
            precision_constraint=precision_constraint,
        )
        if new_modified_property <= old_modified_property:
            raise InvalidValueError(
                cls, 'modified',
                "The new modified datetime cannot be before than or equal to the current modified datetime."
                "It cannot be equal, as according to STIX 2 specification, objects that are different "
                "but have the same id and modified timestamp do not have defined consumer behavior.",
            )
    new_obj_inner.update(kwargs)

    # Set allow_custom appropriately if versioning an object.  We will ignore
    # it for dicts.
    if isinstance(data, stix2.base._STIXBase):
        if allow_custom is None:
            new_obj_inner["allow_custom"] = data._allow_custom
        else:
            new_obj_inner["allow_custom"] = allow_custom

    # Exclude properties with a value of 'None' in case data is not an instance of a _STIXBase subclass
    return cls(**{k: v for k, v in new_obj_inner.items() if v is not None})


def revoke(data):
    """Revoke a STIX object.

    Returns:
        A new version of the object with ``revoked`` set to ``True``.
    """
    if not isinstance(data, Mapping):
        raise ValueError(
            "cannot revoke object of this type! Try a dictionary "
            "or instance of an SDO or SRO class.",
        )

    if data.get('revoked'):
        raise RevokeError("revoke")
    return new_version(data, revoked=True)


def remove_custom_stix(stix_obj):
    """Remove any custom STIX objects or properties.

    Warnings:
        This function is a best effort utility, in that it will remove custom
        objects and properties based on the type names; i.e. if "x-" prefixes
        object types, and "x\\_" prefixes property types. According to the
        STIX2 spec, those naming conventions are a SHOULDs not MUSTs, meaning
        that valid custom STIX content may ignore those conventions and in
        effect render this utility function invalid when used on that STIX
        content.

    Args:
        stix_obj (dict OR python-stix obj): a single python-stix object
                                             or dict of a STIX object

    Returns:
        A new version of the object with any custom content removed
    """

    if stix_obj['type'].startswith('x-'):
        # if entire object is custom, discard
        return None

    custom_props = {
        k: None
        for k in stix_obj if k.startswith("x_")
    }

    if custom_props:
        new_obj = new_version(stix_obj, allow_custom=False, **custom_props)

        return new_obj

    else:
        return stix_obj
