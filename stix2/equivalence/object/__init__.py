"""Python APIs for STIX 2 Object-based Semantic Equivalence."""
import logging
import time

from ...datastore import Filter
from ...utils import STIXdatetime, parse_into_datetime
from ..pattern import equivalent_patterns

logger = logging.getLogger(__name__)


def semantically_equivalent(obj1, obj2, prop_scores={}, **weight_dict):
    """This method verifies if two objects of the same type are
    semantically equivalent.

    Args:
        obj1: A stix2 object instance
        obj2: A stix2 object instance
        prop_scores: A dictionary that can hold individual property scores,
            weights, contributing score, matching score and sum of weights.
        weight_dict: A dictionary that can be used to override settings
            in the semantic equivalence process

    Returns:
        float: A number between 0.0 and 100.0 as a measurement of equivalence.

    Warning:
        Object types need to have property weights defined for the equivalence process.
        Otherwise, those objects will not influence the final score. The WEIGHTS
        dictionary under `stix2.equivalence.object` can give you an idea on how to add
        new entries and pass them via the `weight_dict` argument. Similarly, the values
        or methods can be fine tuned for a particular use case.

    Note:
        Default weights_dict:

        .. include:: ../../object_default_sem_eq_weights.rst

    Note:
        This implementation follows the Semantic Equivalence Committee Note.
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
                if check_property_present(prop, obj1, obj2):
                    w = weights[type1][prop][0]
                    comp_funct = weights[type1][prop][1]

                    if comp_funct == partial_timestamp_based:
                        contributing_score = w * comp_funct(obj1[prop], obj2[prop], weights[type1]["tdelta"])
                    elif comp_funct == partial_location_distance:
                        threshold = weights[type1]["threshold"]
                        contributing_score = w * comp_funct(obj1["latitude"], obj1["longitude"], obj2["latitude"], obj2["longitude"], threshold)
                    elif comp_funct == reference_check or comp_funct == list_reference_check:
                        max_depth = weights["_internal"]["max_depth"]
                        if max_depth < 0:
                            continue  # prevent excessive recursion
                        else:
                            weights["_internal"]["max_depth"] -= 1
                        ds1, ds2 = weights["_internal"]["ds1"], weights["_internal"]["ds2"]
                        contributing_score = w * comp_funct(obj1[prop], obj2[prop], ds1, ds2, **weights)
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
    if prop == "longitude_latitude":
        if all(x in obj1 and x in obj2 for x in ['latitude', 'longitude']):
            return True
    elif prop in obj1 and prop in obj2:
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
    result = len(l1_set.intersection(l2_set)) / max(len(l1_set), len(l2_set))
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
    from rapidfuzz import fuzz
    result = fuzz.token_sort_ratio(str1, str2)
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
    return equivalent_patterns(pattern1, pattern2)


def partial_external_reference_based(refs1, refs2):
    """Performs a matching on External References.

    Args:
        refs1: A list of external references.
        refs2: A list of external references.

    Returns:
        float: Number between 0.0 and 1.0 depending on matches.

    """
    allowed = {"veris", "cve", "capec", "mitre-attack"}
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
    from haversine import Unit, haversine
    distance = haversine((lat1, long1), (lat2, long2), unit=Unit.KILOMETERS)
    result = 1 - (distance / threshold)
    logger.debug(
        "--\t\tpartial_location_distance '%s' '%s' threshold: '%s'\tresult: '%s'",
        (lat1, long1), (lat2, long2), threshold, result,
    )
    return result


def _versioned_checks(ref1, ref2, ds1, ds2, **weights):
    """Checks multiple object versions if present in graph.
    Maximizes for the semantic equivalence score of a particular version."""
    results = {}
    objects1 = ds1.query([Filter("id", "=", ref1)])
    objects2 = ds2.query([Filter("id", "=", ref2)])

    if len(objects1) > 0 and len(objects2) > 0:
        for o1 in objects1:
            for o2 in objects2:
                result = semantically_equivalent(o1, o2, **weights)
                if ref1 not in results:
                    results[ref1] = {"matched": ref2, "value": result}
                elif result > results[ref1]["value"]:
                    results[ref1] = {"matched": ref2, "value": result}
    result = results.get(ref1, {}).get("value", 0.0)
    logger.debug(
        "--\t\t_versioned_checks '%s' '%s'\tresult: '%s'",
        ref1, ref2, result,
    )
    return result


def reference_check(ref1, ref2, ds1, ds2, **weights):
    """For two references, de-reference the object and perform object-based
    semantic equivalence. The score influences the result of an edge check."""
    type1, type2 = ref1.split("--")[0], ref2.split("--")[0]
    result = 0.0

    if type1 == type2:
        if weights["_internal"]["versioning_checks"]:
            result = _versioned_checks(ref1, ref2, ds1, ds2, **weights) / 100.0
        else:
            o1, o2 = ds1.get(ref1), ds2.get(ref2)
            if o1 and o2:
                result = semantically_equivalent(o1, o2, **weights) / 100.0

    logger.debug(
        "--\t\treference_check '%s' '%s'\tresult: '%s'",
        ref1, ref2, result,
    )
    return result


def list_reference_check(refs1, refs2, ds1, ds2, **weights):
    """For objects that contain multiple references (i.e., object_refs) perform
    the same de-reference procedure and perform object-based semantic equivalence.
    The score influences the objects containing these references. The result is
    weighted on the amount of unique objects that could 1) be de-referenced 2) """
    results = {}
    if len(refs1) >= len(refs2):
        l1 = refs1
        l2 = refs2
        b1 = ds1
        b2 = ds2
    else:
        l1 = refs2
        l2 = refs1
        b1 = ds2
        b2 = ds1

    l1.sort()
    l2.sort()

    for ref1 in l1:
        for ref2 in l2:
            type1, type2 = ref1.split("--")[0], ref2.split("--")[0]
            if type1 == type2:
                score = reference_check(ref1, ref2, b1, b2, **weights) * 100.0

                if ref1 not in results:
                    results[ref1] = {"matched": ref2, "value": score}
                elif score > results[ref1]["value"]:
                    results[ref1] = {"matched": ref2, "value": score}

    result = 0.0
    total_sum = sum(x["value"] for x in results.values())
    max_score = len(results) * 100.0

    if max_score > 0:
        result = total_sum / max_score

    logger.debug(
        "--\t\tlist_reference_check '%s' '%s'\ttotal_sum: '%s'\tmax_score: '%s'\tresult: '%s'",
        refs1, refs2, total_sum, max_score, result,
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
    "course-of-action": {
        "name": (60, partial_string_based),
        "external_references": (40, partial_external_reference_based),
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
    "intrusion-set": {
        "name": (20, partial_string_based),
        "external_references": (60, partial_external_reference_based),
        "aliases": (20, partial_list_based),
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
    "marking-definition": {
        "name": (20, exact_match),
        "definition": (60, exact_match),
        "definition_type": (20, exact_match),
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
}  # :autodoc-skip:
