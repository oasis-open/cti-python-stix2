"""Python APIs for STIX 2 Graph-based Semantic Equivalence."""
import collections
import itertools
import logging

from ..object import (
    WEIGHTS, exact_match, list_reference_check, partial_string_based,
    partial_timestamp_based, reference_check, object_similarity,
)

logger = logging.getLogger(__name__)


def graph_similarity(ds1, ds2, prop_scores={}, **weight_dict):
    """This method verifies if two graphs are semantically equivalent.
    Each DataStore can contain a connected or disconnected graph and the
    final result is weighted over the amount of objects we managed to compare.
    This approach builds on top of the object-based semantic equivalence process
    and each comparison can return a value between 0 and 100.

    Args:
        ds1: A DataStore object instance representing your graph
        ds2: A DataStore object instance representing your graph
        prop_scores: A dictionary that can hold individual property scores,
            weights, contributing score, matching score and sum of weights.
        weight_dict: A dictionary that can be used to override settings
            in the semantic equivalence process

    Returns:
        float: A number between 0.0 and 100.0 as a measurement of equivalence.

    Warning:
        Object types need to have property weights defined for the equivalence process.
        Otherwise, those objects will not influence the final score. The WEIGHTS
        dictionary under `stix2.equivalence.graph` can give you an idea on how to add
        new entries and pass them via the `weight_dict` argument. Similarly, the values
        or methods can be fine tuned for a particular use case.

    Note:
        Default weights_dict:

        .. include:: ../../graph_default_sem_eq_weights.rst

    Note:
        This implementation follows the Semantic Equivalence Committee Note.
        see `the Committee Note <link here>`__.

    """
    results = {}
    equivalence_score = 0
    weights = GRAPH_WEIGHTS.copy()

    if weight_dict:
        weights.update(weight_dict)

    depth = weights["_internal"]["max_depth"]

    graph1 = bucket_per_type(ds1.query([]))
    graph2 = bucket_per_type(ds2.query([]))
    pairs = object_pairs(graph1, graph2, weights)

    for object1, object2 in pairs:
        iprop_score1 = {}
        iprop_score2 = {}
        object1_id = object1["id"]
        object2_id = object2["id"]
        weights["_internal"]["max_depth"] = depth
        weights["_internal"]["ds1"] = ds1
        weights["_internal"]["ds2"] = ds2
        result1 = object_similarity(object1, object2, iprop_score1, **weights)

        weights["_internal"]["ds1"] = ds2
        weights["_internal"]["ds2"] = ds1
        result2 = object_similarity(object2, object1, iprop_score2, **weights)

        if object1_id not in results:
            results[object1_id] = {"lhs": object1["id"], "rhs": object2["id"], "prop_score": iprop_score1, "value": result1}
        elif result1 > results[object1_id]["value"]:
            results[object1_id] = {"lhs": object1["id"], "rhs": object2["id"], "prop_score": iprop_score1, "value": result1}

        if object2_id not in results:
            results[object2_id] = {"lhs": object2["id"], "rhs": object1["id"], "prop_score": iprop_score2, "value": result2}
        elif result1 > results[object2_id]["value"]:
            results[object2_id] = {"lhs": object2["id"], "rhs": object1["id"], "prop_score": iprop_score2, "value": result2}

    matching_score = sum(x["value"] for x in results.values())
    sum_weights = len(results)
    if sum_weights > 0:
        equivalence_score = matching_score / sum_weights

    prop_scores["matching_score"] = matching_score
    prop_scores["sum_weights"] = sum_weights
    prop_scores["summary"] = results

    logger.debug(
        "DONE\t\tSUM_WEIGHT: %.2f\tMATCHING_SCORE: %.2f\t SCORE: %.2f",
        sum_weights,
        matching_score,
        equivalence_score,
    )
    return equivalence_score


def bucket_per_type(g):
    buckets = collections.defaultdict(list)
    [buckets[obj["type"]].append(obj) for obj in g]
    return buckets


def object_pairs(g1, g2, w):
    types_in_common = set(g1.keys()).intersection(g2.keys())
    testable_types = types_in_common.intersection(w.keys())

    return itertools.chain.from_iterable(
        itertools.product(g1[stix_type], g2[stix_type])
        for stix_type in testable_types
    )


# default weights used for the graph semantic equivalence process
GRAPH_WEIGHTS = WEIGHTS.copy()
GRAPH_WEIGHTS.update({
    "grouping": {
        "name": (20, partial_string_based),
        "context": (20, partial_string_based),
        "object_refs": (60, list_reference_check),
    },
    "relationship": {
        "relationship_type": (20, exact_match),
        "source_ref": (40, reference_check),
        "target_ref": (40, reference_check),
    },
    "report": {
        "name": (30, partial_string_based),
        "published": (10, partial_timestamp_based),
        "object_refs": (60, list_reference_check),
        "tdelta": 1,  # One day interval
    },
    "sighting": {
        "first_seen": (5, partial_timestamp_based),
        "last_seen": (5, partial_timestamp_based),
        "sighting_of_ref": (40, reference_check),
        "observed_data_refs": (20, list_reference_check),
        "where_sighted_refs": (20, list_reference_check),
        "summary": (10, exact_match),
    },
    "_internal": {
        "ignore_spec_version": False,
        "versioning_checks": False,
        "ds1": None,
        "ds2": None,
        "max_depth": 1,
    },
})  # :autodoc-skip:
