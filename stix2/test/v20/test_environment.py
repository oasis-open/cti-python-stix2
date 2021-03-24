import json
import os

import pytest

import stix2
import stix2.equivalence.graph
import stix2.equivalence.object

from .constants import (
    CAMPAIGN_ID, CAMPAIGN_KWARGS, FAKE_TIME, IDENTITY_ID, IDENTITY_KWARGS,
    INDICATOR_ID, INDICATOR_KWARGS, MALWARE_ID, MALWARE_KWARGS,
    RELATIONSHIP_IDS,
)

FS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "stix2_data")


@pytest.fixture
def ds():
    cam = stix2.v20.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = stix2.v20.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = stix2.v20.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    mal = stix2.v20.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    rel1 = stix2.v20.Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = stix2.v20.Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = stix2.v20.Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    reprt = stix2.v20.Report(
        name="Malware Report",
        published="2021-05-09T08:22:22Z",
        labels=["campaign"],
        object_refs=[mal.id, rel1.id, ind.id],
    )
    stix_objs = [cam, idy, ind, mal, rel1, rel2, rel3, reprt]
    yield stix2.MemoryStore(stix_objs)


@pytest.fixture
def ds2():
    cam = stix2.v20.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = stix2.v20.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = stix2.v20.Indicator(id=INDICATOR_ID, created_by_ref=idy.id, **INDICATOR_KWARGS)
    indv2 = ind.new_version(
        external_references=[{
            "source_name": "unknown",
            "url": "https://examplewebsite.com/",
        }],
    )
    mal = stix2.v20.Malware(id=MALWARE_ID, created_by_ref=idy.id, **MALWARE_KWARGS)
    malv2 = mal.new_version(
        external_references=[{
            "source_name": "unknown",
            "url": "https://examplewebsite2.com/",
        }],
    )
    rel1 = stix2.v20.Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = stix2.v20.Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = stix2.v20.Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    stix_objs = [cam, idy, ind, indv2, mal, malv2, rel1, rel2, rel3]
    reprt = stix2.v20.Report(
        created_by_ref=idy.id,
        name="example",
        labels=["campaign"],
        published="2021-04-09T08:22:22Z",
        object_refs=stix_objs,
    )
    stix_objs.append(reprt)
    yield stix2.MemoryStore(stix_objs)


@pytest.fixture
def fs():
    yield stix2.FileSystemSource(FS_PATH)


def test_object_factory_created_by_ref_str():
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID)
    ind = factory.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID


def test_object_factory_created_by_ref_obj():
    id_obj = stix2.v20.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=id_obj)
    ind = factory.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID


def test_object_factory_override_default():
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID)
    new_id = "identity--983b3172-44fe-4a80-8091-eb8098841fe8"
    ind = factory.create(stix2.v20.Indicator, created_by_ref=new_id, **INDICATOR_KWARGS)
    assert ind.created_by_ref == new_id


def test_object_factory_created():
    factory = stix2.ObjectFactory(created=FAKE_TIME)
    ind = factory.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    assert ind.created == FAKE_TIME
    assert ind.modified == FAKE_TIME


def test_object_factory_external_reference():
    ext_ref = stix2.v20.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
    )
    factory = stix2.ObjectFactory(external_references=ext_ref)
    ind = factory.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    assert ind.external_references[0].source_name == "ACME Threat Intel"
    assert ind.external_references[0].description == "Threat report"

    ind2 = factory.create(stix2.v20.Indicator, external_references=None, **INDICATOR_KWARGS)
    assert 'external_references' not in ind2


def test_object_factory_obj_markings():
    stmt_marking = stix2.v20.StatementMarking("Copyright 2016, Example Corp")
    mark_def = stix2.v20.MarkingDefinition(
        definition_type="statement",
        definition=stmt_marking,
    )
    factory = stix2.ObjectFactory(object_marking_refs=[mark_def, stix2.v20.TLP_AMBER])
    ind = factory.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    assert mark_def.id in ind.object_marking_refs
    assert stix2.v20.TLP_AMBER.id in ind.object_marking_refs

    factory = stix2.ObjectFactory(object_marking_refs=stix2.v20.TLP_RED)
    ind = factory.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    assert stix2.v20.TLP_RED.id in ind.object_marking_refs


def test_object_factory_list_append():
    ext_ref = stix2.v20.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report from ACME",
    )
    ext_ref2 = stix2.v20.ExternalReference(
        source_name="Yet Another Threat Report",
        description="Threat report from YATR",
    )
    ext_ref3 = stix2.v20.ExternalReference(
        source_name="Threat Report #3",
        description="One more threat report",
    )
    factory = stix2.ObjectFactory(external_references=ext_ref)
    ind = factory.create(stix2.v20.Indicator, external_references=ext_ref2, **INDICATOR_KWARGS)
    assert ind.external_references[1].source_name == "Yet Another Threat Report"

    ind = factory.create(stix2.v20.Indicator, external_references=[ext_ref2, ext_ref3], **INDICATOR_KWARGS)
    assert ind.external_references[2].source_name == "Threat Report #3"


def test_object_factory_list_replace():
    ext_ref = stix2.v20.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report from ACME",
    )
    ext_ref2 = stix2.v20.ExternalReference(
        source_name="Yet Another Threat Report",
        description="Threat report from YATR",
    )
    factory = stix2.ObjectFactory(external_references=ext_ref, list_append=False)
    ind = factory.create(stix2.v20.Indicator, external_references=ext_ref2, **INDICATOR_KWARGS)
    assert len(ind.external_references) == 1
    assert ind.external_references[0].source_name == "Yet Another Threat Report"


def test_environment_functions():
    env = stix2.Environment(
        stix2.ObjectFactory(created_by_ref=IDENTITY_ID),
        stix2.MemoryStore(),
    )

    # Create a STIX object
    ind = env.create(stix2.v20.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID

    # Add objects to datastore
    ind2 = ind.new_version(labels=['benign'])
    env.add([ind, ind2])

    # Get both versions of the object
    resp = env.all_versions(INDICATOR_ID)
    assert len(resp) == 2

    # Get just the most recent version of the object
    resp = env.get(INDICATOR_ID)
    assert resp['labels'][0] == 'benign'

    # Search on something other than id
    query = [stix2.Filter('type', '=', 'vulnerability')]
    resp = env.query(query)
    assert len(resp) == 0

    # See different results after adding filters to the environment
    env.add_filters([
        stix2.Filter('type', '=', 'indicator'),
        stix2.Filter('created_by_ref', '=', IDENTITY_ID),
    ])
    env.add_filter(stix2.Filter('labels', '=', 'benign'))  # should be 'malicious-activity'
    resp = env.get(INDICATOR_ID)
    assert resp['labels'][0] == 'benign'  # should be 'malicious-activity'


def test_environment_source_and_sink():
    ind = stix2.v20.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    env = stix2.Environment(source=stix2.MemorySource([ind]), sink=stix2.MemorySink([ind]))
    assert env.get(INDICATOR_ID).labels[0] == 'malicious-activity'


def test_environment_datastore_and_sink():
    with pytest.raises(ValueError) as excinfo:
        stix2.Environment(
            factory=stix2.ObjectFactory(),
            store=stix2.MemoryStore(), sink=stix2.MemorySink,
        )
    assert 'Data store already provided' in str(excinfo.value)


def test_environment_no_datastore():
    env = stix2.Environment(factory=stix2.ObjectFactory())

    with pytest.raises(AttributeError) as excinfo:
        env.add(stix2.v20.Indicator(**INDICATOR_KWARGS))
    assert 'Environment has no data sink to put objects in' in str(excinfo.value)

    with pytest.raises(AttributeError) as excinfo:
        env.get(INDICATOR_ID)
    assert 'Environment has no data source' in str(excinfo.value)

    with pytest.raises(AttributeError) as excinfo:
        env.all_versions(INDICATOR_ID)
    assert 'Environment has no data source' in str(excinfo.value)

    with pytest.raises(AttributeError) as excinfo:
        env.query(INDICATOR_ID)
    assert 'Environment has no data source' in str(excinfo.value)

    with pytest.raises(AttributeError) as excinfo:
        env.relationships(INDICATOR_ID)
    assert 'Environment has no data source' in str(excinfo.value)

    with pytest.raises(AttributeError) as excinfo:
        env.related_to(INDICATOR_ID)
    assert 'Environment has no data source' in str(excinfo.value)


def test_environment_add_filters():
    env = stix2.Environment(factory=stix2.ObjectFactory())
    env.add_filters([INDICATOR_ID])
    env.add_filter(INDICATOR_ID)


def test_environment_datastore_and_no_object_factory():
    # Uses a default object factory
    env = stix2.Environment(store=stix2.MemoryStore())
    ind = env.create(stix2.v20.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    assert ind.id == INDICATOR_ID


def test_parse_malware():
    env = stix2.Environment()
    data = """{
        "type": "malware",
        "id": "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        "created": "2017-01-01T12:34:56.000Z",
        "modified": "2017-01-01T12:34:56.000Z",
        "name": "Cryptolocker",
        "labels": [
            "ransomware"
        ]
    }"""
    mal = env.parse(data, version="2.0")

    assert mal.type == 'malware'
    assert mal.id == MALWARE_ID
    assert mal.created == FAKE_TIME
    assert mal.modified == FAKE_TIME
    assert mal.labels == ['ransomware']
    assert mal.name == "Cryptolocker"


def test_creator_of():
    identity = stix2.v20.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(store=stix2.MemoryStore(), factory=factory)
    env.add(identity)

    ind = env.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is identity


def test_creator_of_no_datasource():
    identity = stix2.v20.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(factory=factory)

    ind = env.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    with pytest.raises(AttributeError) as excinfo:
        env.creator_of(ind)
    assert 'Environment has no data source' in str(excinfo.value)


def test_creator_of_not_found():
    identity = stix2.v20.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(store=stix2.MemoryStore(), factory=factory)

    ind = env.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is None


def test_creator_of_no_created_by_ref():
    env = stix2.Environment(store=stix2.MemoryStore())
    ind = env.create(stix2.v20.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is None


def test_relationships(ds):
    env = stix2.Environment(store=ds)
    mal = env.get(MALWARE_ID)
    resp = env.relationships(mal)

    assert len(resp) == 3
    assert any(x['id'] == RELATIONSHIP_IDS[0] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[1] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_no_id(ds):
    env = stix2.Environment(store=ds)
    mal = {
        "type": "malware",
        "name": "some variant",
    }
    with pytest.raises(ValueError) as excinfo:
        env.relationships(mal)
    assert "object has no 'id' property" in str(excinfo.value)


def test_relationships_by_type(ds):
    env = stix2.Environment(store=ds)
    mal = env.get(MALWARE_ID)
    resp = env.relationships(mal, relationship_type='indicates')

    assert len(resp) == 1
    assert resp[0]['id'] == RELATIONSHIP_IDS[0]


def test_relationships_by_source(ds):
    env = stix2.Environment(store=ds)
    resp = env.relationships(MALWARE_ID, source_only=True)

    assert len(resp) == 1
    assert resp[0]['id'] == RELATIONSHIP_IDS[1]


def test_relationships_by_target(ds):
    env = stix2.Environment(store=ds)
    resp = env.relationships(MALWARE_ID, target_only=True)

    assert len(resp) == 2
    assert any(x['id'] == RELATIONSHIP_IDS[0] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_target_and_type(ds):
    env = stix2.Environment(store=ds)
    resp = env.relationships(MALWARE_ID, relationship_type='uses', target_only=True)

    assert len(resp) == 1
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_target_and_source(ds):
    env = stix2.Environment(store=ds)
    with pytest.raises(ValueError) as excinfo:
        env.relationships(MALWARE_ID, target_only=True, source_only=True)

    assert 'not both' in str(excinfo.value)


def test_related_to(ds):
    env = stix2.Environment(store=ds)
    mal = env.get(MALWARE_ID)
    resp = env.related_to(mal)

    assert len(resp) == 3
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)
    assert any(x['id'] == IDENTITY_ID for x in resp)


def test_related_to_no_id(ds):
    env = stix2.Environment(store=ds)
    mal = {
        "type": "malware",
        "name": "some variant",
    }
    with pytest.raises(ValueError) as excinfo:
        env.related_to(mal)
    assert "object has no 'id' property" in str(excinfo.value)


def test_related_to_by_source(ds):
    env = stix2.Environment(store=ds)
    resp = env.related_to(MALWARE_ID, source_only=True)

    assert len(resp) == 1
    assert resp[0]['id'] == IDENTITY_ID


def test_related_to_by_target(ds):
    env = stix2.Environment(store=ds)
    resp = env.related_to(MALWARE_ID, target_only=True)

    assert len(resp) == 2
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)


def test_versioned_checks(ds, ds2):
    weights = stix2.equivalence.graph.WEIGHTS.copy()
    weights.update({
        "_internal": {
            "ignore_spec_version": True,
            "versioning_checks": True,
            "max_depth": 1,
        },
    })
    score = stix2.equivalence.object._versioned_checks(INDICATOR_ID, INDICATOR_ID, ds, ds2, **weights)
    assert round(score) == 100


def test_semantic_check_with_versioning(ds, ds2):
    weights = stix2.equivalence.graph.WEIGHTS.copy()
    weights.update({
        "_internal": {
            "ignore_spec_version": False,
            "versioning_checks": True,
            "ds1": ds,
            "ds2": ds2,
            "max_depth": 1,
        },
    })
    ind = stix2.v20.Indicator(
        **dict(
            labels=["malicious-activity"],
            pattern="[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
            valid_from="2017-01-01T12:34:56Z",
            external_references=[
                {
                  "source_name": "unknown",
                  "url": "https://examplewebsite2.com/",
                },
            ],
            object_marking_refs=[stix2.v20.TLP_WHITE],
        )
    )
    ds.add(ind)
    score = stix2.equivalence.object.reference_check(ind.id, INDICATOR_ID, ds, ds2, **weights)
    assert round(score) == 0  # Since pattern is different score is really low


def test_list_semantic_check(ds, ds2):
    weights = stix2.equivalence.graph.WEIGHTS.copy()
    weights.update({
        "_internal": {
            "ignore_spec_version": False,
            "versioning_checks": False,
            "max_depth": 1,
        },
    })
    object_refs1 = [
        "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        "relationship--06520621-5352-4e6a-b976-e8fa3d437ffd",
        "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
    ]
    object_refs2 = [
        "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
        "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
        "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        "relationship--06520621-5352-4e6a-b976-e8fa3d437ffd",
        "relationship--181c9c09-43e6-45dd-9374-3bec192f05ef",
        "relationship--a0cbb21c-8daf-4a7f-96aa-7155a4ef8f70",
    ]

    score = stix2.equivalence.object.list_reference_check(
        object_refs1,
        object_refs2,
        ds,
        ds2,
        **weights,
    )
    assert round(score) == 1


def test_graph_similarity_raises_value_error(ds):
    with pytest.raises(ValueError):
        prop_scores1 = {}
        stix2.Environment().graph_similarity(ds, ds2, prop_scores1, max_depth=-1)


def test_graph_similarity_with_filesystem_source(ds, fs):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_similarity(fs, ds, prop_scores1, ignore_spec_version=True)

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_similarity(ds, fs, prop_scores2, ignore_spec_version=True)

    assert round(env1) == 25
    assert round(prop_scores1["matching_score"]) == 451
    assert round(prop_scores1["len_pairs"]) == 18

    assert round(env2) == 25
    assert round(prop_scores2["matching_score"]) == 451
    assert round(prop_scores2["len_pairs"]) == 18

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_graph_similarity_with_duplicate_graph(ds):
    prop_scores = {}
    env = stix2.Environment().graph_similarity(ds, ds, prop_scores)
    assert round(env) == 100
    assert round(prop_scores["matching_score"]) == 800
    assert round(prop_scores["len_pairs"]) == 8


def test_graph_similarity_with_versioning_check_on(ds2, ds):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_similarity(ds, ds2, prop_scores1, versioning_checks=True)

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_similarity(ds2, ds, prop_scores2, versioning_checks=True)

    assert round(env1) == 88
    assert round(prop_scores1["matching_score"]) == 789
    assert round(prop_scores1["len_pairs"]) == 9

    assert round(env2) == 88
    assert round(prop_scores2["matching_score"]) == 789
    assert round(prop_scores2["len_pairs"]) == 9

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_graph_similarity_with_versioning_check_off(ds2, ds):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_similarity(ds, ds2, prop_scores1)

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_similarity(ds2, ds, prop_scores2)

    assert round(env1) == 88
    assert round(prop_scores1["matching_score"]) == 789
    assert round(prop_scores1["len_pairs"]) == 9

    assert round(env2) == 88
    assert round(prop_scores2["matching_score"]) == 789
    assert round(prop_scores2["len_pairs"]) == 9

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_graph_equivalence_with_filesystem_source(ds, fs):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_equivalence(fs, ds, prop_scores1, ignore_spec_version=True)

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_equivalence(ds, fs, prop_scores2, ignore_spec_version=True)

    assert env1 is False
    assert round(prop_scores1["matching_score"]) == 451
    assert round(prop_scores1["len_pairs"]) == 18

    assert env2 is False
    assert round(prop_scores2["matching_score"]) == 451
    assert round(prop_scores2["len_pairs"]) == 18

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_graph_equivalence_with_duplicate_graph(ds):
    prop_scores = {}
    env = stix2.Environment().graph_equivalence(ds, ds, prop_scores)
    assert env is True
    assert round(prop_scores["matching_score"]) == 800
    assert round(prop_scores["len_pairs"]) == 8


def test_graph_equivalence_with_versioning_check_on(ds2, ds):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_equivalence(ds, ds2, prop_scores1, versioning_checks=True)

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_equivalence(ds2, ds, prop_scores2, versioning_checks=True)

    assert env1 is True
    assert round(prop_scores1["matching_score"]) == 789
    assert round(prop_scores1["len_pairs"]) == 9

    assert env2 is True
    assert round(prop_scores2["matching_score"]) == 789
    assert round(prop_scores2["len_pairs"]) == 9

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_graph_equivalence_with_versioning_check_off(ds2, ds):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_equivalence(ds, ds2, prop_scores1)

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_equivalence(ds2, ds, prop_scores2)

    assert env1 is True
    assert round(prop_scores1["matching_score"]) == 789
    assert round(prop_scores1["len_pairs"]) == 9

    assert env2 is True
    assert round(prop_scores2["matching_score"]) == 789
    assert round(prop_scores2["len_pairs"]) == 9

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)
