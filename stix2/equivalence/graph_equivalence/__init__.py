import logging

from ..object_equivalence import (
    custom_pattern_based, exact_match, list_semantic_check,
    partial_external_reference_based, partial_list_based,
    partial_location_distance, partial_string_based, partial_timestamp_based,
    semantic_check, semantically_equivalent,
)

logger = logging.getLogger(__name__)


def graphically_equivalent(ds1, ds2, prop_scores={}, **weight_dict):
    """This method is meant to verify if two graphs are semantically
    equivalent.

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
        Some object types do not have an entry for use in the equivalence process.
        In order for those objects to influence the final score a new entry needs to
        be defined in the WEIGHTS dictionary. Similarly, the values can be fine tuned
        for a particular use case. Graph equivalence has additional entries.

    Note:
        Default weights_dict:

        .. include:: ../default_sem_eq_weights.rst

    """
    weights = WEIGHTS.copy()

    if weight_dict:
        weights.update(weight_dict)

    results = {}

    graph1 = ds1.query([])
    graph2 = ds2.query([])

    graph1.sort(key=lambda x: x["type"])
    graph2.sort(key=lambda x: x["type"])

    if len(graph1) < len(graph2):
        weights["_internal"]["ds1"] = ds1
        weights["_internal"]["ds2"] = ds2
        g1 = graph1
        g2 = graph2
    else:
        weights["_internal"]["ds1"] = ds2
        weights["_internal"]["ds2"] = ds1
        g1 = graph2
        g2 = graph1

    for object1 in g1:
        for object2 in g2:
            if object1["type"] == object2["type"]:
                result = semantically_equivalent(object1, object2, prop_scores, **weights)
                objects1_id = object1["id"]
                if objects1_id not in results:
                    results[objects1_id] = {"matched": object2["id"], "value": result}
                elif result > results[objects1_id]["value"]:
                    results[objects1_id] = {"matched": object2["id"], "value": result}

    sum_weights = sum(x["value"] for x in results.values())
    matching_score = len(g1) * 100.0
    equivalence_score = (sum_weights / matching_score) * 100

    logger.debug(f"DONE\nPOINT_SUM: {sum_weights:.2f}\tMAX_SCORE: {matching_score:.2f}\t PERCENTAGE: {equivalence_score:.2f}")
    return equivalence_score


# default weights used for the graph semantic equivalence process
# values are re-balanced to account for new property checks and add up to 100
WEIGHTS = {
    "attack-pattern": {
        "name": (30, partial_string_based),
        "external_references": (60, partial_external_reference_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "campaign": {
        "name": (50, partial_string_based),
        "aliases": (40, partial_list_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "course-of-action": {
        "name": (30, partial_string_based),
        "external_references": (60, partial_external_reference_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "identity": {
        "name": (50, partial_string_based),
        "identity_class": (20, exact_match),
        "sectors": (20, partial_list_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "indicator": {
        "indicator_types": (15, partial_list_based),
        "pattern": (70, custom_pattern_based),
        "valid_from": (5, partial_timestamp_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
        "tdelta": 1,  # One day interval
    },
    "intrusion-set": {
        "name": (10, partial_string_based),
        "external_references": (60, partial_external_reference_based),
        "aliases": (20, partial_list_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "location": {
        "longitude_latitude": (30, partial_location_distance),
        "region": (30, exact_match),
        "country": (30, exact_match),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
        "threshold": 1000.0,
    },
    "malware": {
        "malware_types": (20, partial_list_based),
        "name": (70, partial_string_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "marking-definition": {
        "definition_type": (90, exact_match),
        # "definition": (30, definition_check),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "threat-actor": {
        "name": (55, partial_string_based),
        "threat_actor_types": (15, partial_list_based),
        "aliases": (20, partial_list_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "tool": {
        "tool_types": (20, partial_list_based),
        "name": (70, partial_string_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "vulnerability": {
        "name": (30, partial_string_based),
        "external_references": (60, partial_external_reference_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "relationship": {
        "source_ref": (43, semantic_check),
        "target_ref": (43, semantic_check),
        "relationship_type": (4, exact_match),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "report": {
        "object_refs": (60, list_semantic_check),
        "name": (30, partial_string_based),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "sighting": {
        "first_seen": (5, partial_timestamp_based),
        "last_seen": (5, partial_timestamp_based),
        "where_sighted_refs": (20, list_semantic_check),
        "observed_data_refs": (20, list_semantic_check),
        "sighting_of_ref": (35, semantic_check),
        "summary": (5, exact_match),
        "created_by_ref": (5, semantic_check),
        "object_marking_refs": (5, list_semantic_check),
    },
    "_internal": {
        "ignore_spec_version": False,
        "versioning_checks": False,
        "ds1": None,
        "ds2": None,
        "max_depth": 1,
    },
}  #: :autodoc-skip:
