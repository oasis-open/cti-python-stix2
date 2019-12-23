"""Python STIX2 Environment API."""

import copy
import logging
import time

from .core import parse as _parse
from .datastore import CompositeDataSource, DataStoreMixin
from .utils import STIXdatetime, parse_into_datetime

logger = logging.getLogger(__name__)


class ObjectFactory(object):
    """Easily create STIX objects with default values for certain properties.

    Args:
        created_by_ref (optional): Default created_by_ref value to apply to all
            objects created by this factory.
        created (optional): Default created value to apply to all
            objects created by this factory.
        external_references (optional): Default `external_references` value to apply
            to all objects created by this factory.
        object_marking_refs (optional): Default `object_marking_refs` value to apply
            to all objects created by this factory.
        list_append (bool, optional): When a default is set for a list property like
            `external_references` or `object_marking_refs` and a value for
            that property is passed into `create()`, if this is set to True,
            that value will be added to the list alongside the default. If
            this is set to False, the passed in value will replace the
            default. Defaults to True.
    """

    def __init__(
        self, created_by_ref=None, created=None,
        external_references=None, object_marking_refs=None,
        list_append=True,
    ):

        self._defaults = {}
        if created_by_ref:
            self.set_default_creator(created_by_ref)
        if created:
            self.set_default_created(created)
        if external_references:
            self.set_default_external_refs(external_references)
        if object_marking_refs:
            self.set_default_object_marking_refs(object_marking_refs)
        self._list_append = list_append
        self._list_properties = ['external_references', 'object_marking_refs']

    def set_default_creator(self, creator=None):
        """Set default value for the `created_by_ref` property.

        """
        self._defaults['created_by_ref'] = creator

    def set_default_created(self, created=None):
        """Set default value for the `created` property.

        """
        self._defaults['created'] = created
        # If the user provides a default "created" time, we also want to use
        # that as the modified time.
        self._defaults['modified'] = created

    def set_default_external_refs(self, external_references=None):
        """Set default external references.

        """
        self._defaults['external_references'] = external_references

    def set_default_object_marking_refs(self, object_marking_refs=None):
        """Set default object markings.

        """
        self._defaults['object_marking_refs'] = object_marking_refs

    def create(self, cls, **kwargs):
        """Create a STIX object using object factory defaults.

        Args:
            cls: the python-stix2 class of the object to be created (eg. Indicator)
            **kwargs: The property/value pairs of the STIX object to be created
        """

        # Use self.defaults as the base, but update with any explicit args
        # provided by the user.
        properties = copy.deepcopy(self._defaults)
        if kwargs:
            if self._list_append:
                # Append provided items to list properties instead of replacing them
                for list_prop in set(self._list_properties).intersection(kwargs.keys(), properties.keys()):
                    kwarg_prop = kwargs.pop(list_prop)
                    if kwarg_prop is None:
                        del properties[list_prop]
                        continue
                    if not isinstance(properties[list_prop], list):
                        properties[list_prop] = [properties[list_prop]]

                    if isinstance(kwarg_prop, list):
                        properties[list_prop].extend(kwarg_prop)
                    else:
                        properties[list_prop].append(kwarg_prop)

            properties.update(**kwargs)

        return cls(**properties)


class Environment(DataStoreMixin):
    """Abstract away some of the nasty details of working with STIX content.

    Args:
        factory (ObjectFactory, optional): Factory for creating objects with common
            defaults for certain properties.
        store (DataStore, optional): Data store providing the source and sink for the
            environment.
        source (DataSource, optional): Source for retrieving STIX objects.
        sink (DataSink, optional): Destination for saving STIX objects.
            Invalid if `store` is also provided.

    .. automethod:: get
    .. automethod:: all_versions
    .. automethod:: query
    .. automethod:: creator_of
    .. automethod:: relationships
    .. automethod:: related_to
    .. automethod:: add

    """

    def __init__(self, factory=ObjectFactory(), store=None, source=None, sink=None):
        self.factory = factory
        self.source = CompositeDataSource()
        if store:
            self.source.add_data_source(store.source)
            self.sink = store.sink
        if source:
            self.source.add_data_source(source)
        if sink:
            if store:
                raise ValueError("Data store already provided! Environment may only have one data sink.")
            self.sink = sink

    def create(self, *args, **kwargs):
        return self.factory.create(*args, **kwargs)
    create.__doc__ = ObjectFactory.create.__doc__

    def set_default_creator(self, *args, **kwargs):
        return self.factory.set_default_creator(*args, **kwargs)
    set_default_creator.__doc__ = ObjectFactory.set_default_creator.__doc__

    def set_default_created(self, *args, **kwargs):
        return self.factory.set_default_created(*args, **kwargs)
    set_default_created.__doc__ = ObjectFactory.set_default_created.__doc__

    def set_default_external_refs(self, *args, **kwargs):
        return self.factory.set_default_external_refs(*args, **kwargs)
    set_default_external_refs.__doc__ = ObjectFactory.set_default_external_refs.__doc__

    def set_default_object_marking_refs(self, *args, **kwargs):
        return self.factory.set_default_object_marking_refs(*args, **kwargs)
    set_default_object_marking_refs.__doc__ = ObjectFactory.set_default_object_marking_refs.__doc__

    def add_filters(self, *args, **kwargs):
        return self.source.filters.add(*args, **kwargs)

    def add_filter(self, *args, **kwargs):
        return self.source.filters.add(*args, **kwargs)

    def parse(self, *args, **kwargs):
        return _parse(*args, **kwargs)
    parse.__doc__ = _parse.__doc__

    def creator_of(self, obj):
        """Retrieve the Identity refered to by the object's `created_by_ref`.

        Args:
            obj: The STIX object whose `created_by_ref` property will be looked
                up.

        Returns:
            str: The STIX object's creator, or None, if the object contains no
                `created_by_ref` property or the object's creator cannot be
                found.

        """
        creator_id = obj.get('created_by_ref', '')
        if creator_id:
            return self.get(creator_id)
        else:
            return None

    @staticmethod
    def semantically_equivalent(obj1, obj2, prop_scores={}, **weight_dict):
        """This method is meant to verify if two objects of the same type are
        semantically equivalent.

        Args:
            obj1: A stix2 object instance
            obj2: A stix2 object instance
            weight_dict: A dictionary that can be used to override settings
                in the semantic equivalence process

        Returns:
            float: A number between 0.0 and 100.0 as a measurement of equivalence.

        Warning:
            Course of Action, Intrusion-Set, Observed-Data, Report are not supported
            by this implementation. Indicator pattern check is also limited.

        Note:
            Default weights_dict:

            .. include:: ../default_sem_eq_weights.rst

        Note:
            This implementation follows the Committee Note on semantic equivalence.
            see `the Committee Note <link here>`__.

        """
        weights = WEIGHTS.copy()

        if weight_dict:
            weights.update(weight_dict)

        type1, type2 = obj1["type"], obj2["type"]
        ignore_spec_version = weights["_internal"]["ignore_spec_version"]

        if type1 != type2:
            raise ValueError('The objects to compare must be of the same type!')

        if ignore_spec_version is False and obj1.get("spec_version", "2.0") != obj2.get("spec_version", "2.0"):
            raise ValueError('The objects to compare must be of the same spec version!')

        try:
            weights[type1]
        except KeyError:
            logger.warning("'%s' type has no 'weights' dict specified & thus no semantic equivalence method to call!", type1)
            sum_weights = matching_score = 0
        else:
            try:
                method = weights[type1]["method"]
            except KeyError:
                logger.debug("Starting semantic equivalence process between: '%s' and '%s'", obj1["id"], obj2["id"])
                matching_score = 0.0
                sum_weights = 0.0

                for prop in weights[type1]:
                    if check_property_present(prop, obj1, obj2) or prop == "longitude_latitude":
                        w = weights[type1][prop][0]
                        comp_funct = weights[type1][prop][1]

                        if comp_funct == partial_timestamp_based:
                            contributing_score = w * comp_funct(obj1[prop], obj2[prop], weights[type1]["tdelta"])
                        elif comp_funct == partial_location_distance:
                            threshold = weights[type1]["threshold"]
                            contributing_score = w * comp_funct(obj1["latitude"], obj1["longitude"], obj2["latitude"], obj2["longitude"], threshold)
                        else:
                            contributing_score = w * comp_funct(obj1[prop], obj2[prop])

                        sum_weights += w
                        matching_score += contributing_score

                        prop_scores[prop] = {
                            "weight": w,
                            "contributing_score": contributing_score,
                        }
                        logger.debug("'%s' check -- weight: %s, contributing score: %s", prop, w, contributing_score)

                prop_scores["matching_score"] = matching_score
                prop_scores["sum_weights"] = sum_weights
                logger.debug("Matching Score: %s, Sum of Weights: %s", matching_score, sum_weights)
            else:
                logger.debug("Starting semantic equivalence process between: '%s' and '%s'", obj1["id"], obj2["id"])
                try:
                    matching_score, sum_weights = method(obj1, obj2, prop_scores, **weights[type1])
                except TypeError:
                    # method doesn't support detailed output with prop_scores
                    matching_score, sum_weights = method(obj1, obj2, **weights[type1])
                logger.debug("Matching Score: %s, Sum of Weights: %s", matching_score, sum_weights)

        if sum_weights <= 0:
            return 0
        equivalence_score = (matching_score / sum_weights) * 100.0
        return equivalence_score


def check_property_present(prop, obj1, obj2):
    """Helper method checks if a property is present on both objects."""
    if prop in obj1 and prop in obj2:
        return True
    return False


def partial_timestamp_based(t1, t2, tdelta):
    """Performs a timestamp-based matching via checking how close one timestamp is to another.

    Args:
        t1: A datetime string or STIXdatetime object.
        t2: A datetime string or STIXdatetime object.
        tdelta (float): A given time delta. This number is multiplied by 86400 (1 day) to
            extend or shrink your time change tolerance.

    Returns:
        float: Number between 0.0 and 1.0 depending on match criteria.

    """
    if not isinstance(t1, STIXdatetime):
        t1 = parse_into_datetime(t1)
    if not isinstance(t2, STIXdatetime):
        t2 = parse_into_datetime(t2)
    t1, t2 = time.mktime(t1.timetuple()), time.mktime(t2.timetuple())
    result = 1 - min(abs(t1 - t2) / (86400 * tdelta), 1)
    logger.debug("--\t\tpartial_timestamp_based '%s' '%s' tdelta: '%s'\tresult: '%s'", t1, t2, tdelta, result)
    return result


def partial_list_based(l1, l2):
    """Performs a partial list matching via finding the intersection between common values.

    Args:
        l1: A list of values.
        l2: A list of values.

    Returns:
        float: 1.0 if the value matches exactly, 0.0 otherwise.

    """
    l1_set, l2_set = set(l1), set(l2)
    result = len(l1_set.intersection(l2_set)) / max(len(l1), len(l2))
    logger.debug("--\t\tpartial_list_based '%s' '%s'\tresult: '%s'", l1, l2, result)
    return result


def exact_match(val1, val2):
    """Performs an exact value match based on two values

    Args:
        val1: A value suitable for an equality test.
        val2: A value suitable for an equality test.

    Returns:
        float: 1.0 if the value matches exactly, 0.0 otherwise.

    """
    result = 0.0
    if val1 == val2:
        result = 1.0
    logger.debug("--\t\texact_match '%s' '%s'\tresult: '%s'", val1, val2, result)
    return result


def partial_string_based(str1, str2):
    """Performs a partial string match using the Jaro-Winkler distance algorithm.

    Args:
        str1: A string value to check.
        str2: A string value to check.

    Returns:
        float: Number between 0.0 and 1.0 depending on match criteria.

    """
    from fuzzywuzzy import fuzz
    result = fuzz.token_sort_ratio(str1, str2, force_ascii=False)
    logger.debug("--\t\tpartial_string_based '%s' '%s'\tresult: '%s'", str1, str2, result)
    return result / 100.0


def custom_pattern_based(pattern1, pattern2):
    """Performs a matching on Indicator Patterns.

    Args:
        pattern1: An Indicator pattern
        pattern2: An Indicator pattern

    Returns:
        float: Number between 0.0 and 1.0 depending on match criteria.

    """
    logger.warning("Indicator pattern equivalence is not fully defined; will default to zero if not completely identical")
    return exact_match(pattern1, pattern2)  # TODO: Implement pattern based equivalence


def partial_external_reference_based(refs1, refs2):
    """Performs a matching on External References.

    Args:
        refs1: A list of external references.
        refs2: A list of external references.

    Returns:
        float: Number between 0.0 and 1.0 depending on matches.

    """
    allowed = set(("veris", "cve", "capec", "mitre-attack"))
    matches = 0

    if len(refs1) >= len(refs2):
        l1 = refs1
        l2 = refs2
    else:
        l1 = refs2
        l2 = refs1

    for ext_ref1 in l1:
        for ext_ref2 in l2:
            sn_match = False
            ei_match = False
            url_match = False
            source_name = None

            if check_property_present("source_name", ext_ref1, ext_ref2):
                if ext_ref1["source_name"] == ext_ref2["source_name"]:
                    source_name = ext_ref1["source_name"]
                    sn_match = True
            if check_property_present("external_id", ext_ref1, ext_ref2):
                if ext_ref1["external_id"] == ext_ref2["external_id"]:
                    ei_match = True
            if check_property_present("url", ext_ref1, ext_ref2):
                if ext_ref1["url"] == ext_ref2["url"]:
                    url_match = True

            # Special case: if source_name is a STIX defined name and either
            # external_id or url match then its a perfect match and other entries
            # can be ignored.
            if sn_match and (ei_match or url_match) and source_name in allowed:
                result = 1.0
                logger.debug(
                    "--\t\tpartial_external_reference_based '%s' '%s'\tresult: '%s'",
                    refs1, refs2, result,
                )
                return result

            # Regular check. If the source_name (not STIX-defined) or external_id or
            # url matches then we consider the entry a match.
            if (sn_match or ei_match or url_match) and source_name not in allowed:
                matches += 1

    result = matches / max(len(refs1), len(refs2))
    logger.debug(
        "--\t\tpartial_external_reference_based '%s' '%s'\tresult: '%s'",
        refs1, refs2, result,
    )
    return result


def partial_location_distance(lat1, long1, lat2, long2, threshold):
    """Given two coordinates perform a matching based on its distance using the Haversine Formula.

    Args:
        lat1: Latitude value for first coordinate point.
        lat2: Latitude value for second coordinate point.
        long1: Longitude value for first coordinate point.
        long2: Longitude value for second coordinate point.
        threshold (float): A kilometer measurement for the threshold distance between these two points.

    Returns:
        float: Number between 0.0 and 1.0 depending on match.

    """
    from haversine import haversine, Unit
    distance = haversine((lat1, long1), (lat2, long2), unit=Unit.KILOMETERS)
    result = 1 - (distance / threshold)
    logger.debug(
        "--\t\tpartial_location_distance '%s' '%s' threshold: '%s'\tresult: '%s'",
        (lat1, long1), (lat2, long2), threshold, result,
    )
    return result


# default weights used for the semantic equivalence process
WEIGHTS = {
    "attack-pattern": {
        "name": (30, partial_string_based),
        "external_references": (70, partial_external_reference_based),
    },
    "campaign": {
        "name": (60, partial_string_based),
        "aliases": (40, partial_list_based),
    },
    "identity": {
        "name": (60, partial_string_based),
        "identity_class": (20, exact_match),
        "sectors": (20, partial_list_based),
    },
    "indicator": {
        "indicator_types": (15, partial_list_based),
        "pattern": (80, custom_pattern_based),
        "valid_from": (5, partial_timestamp_based),
        "tdelta": 1,  # One day interval
    },
    "location": {
        "longitude_latitude": (34, partial_location_distance),
        "region": (33, exact_match),
        "country": (33, exact_match),
        "threshold": 1000.0,
    },
    "malware": {
        "malware_types": (20, partial_list_based),
        "name": (80, partial_string_based),
    },
    "threat-actor": {
        "name": (60, partial_string_based),
        "threat_actor_types": (20, partial_list_based),
        "aliases": (20, partial_list_based),
    },
    "tool": {
        "tool_types": (20, partial_list_based),
        "name": (80, partial_string_based),
    },
    "vulnerability": {
        "name": (30, partial_string_based),
        "external_references": (70, partial_external_reference_based),
    },
    "_internal": {
        "ignore_spec_version": False,
    },
}  #: :autodoc-skip:
