import json
import os

import pytest

import stix2
import stix2.environment
import stix2.equivalence.graph
import stix2.equivalence.object
import stix2.exceptions

from .constants import (
    ATTACK_PATTERN_ID, ATTACK_PATTERN_KWARGS, CAMPAIGN_ID, CAMPAIGN_KWARGS,
    FAKE_TIME, IDENTITY_ID, IDENTITY_KWARGS, INDICATOR_ID, INDICATOR_KWARGS,
    LOCATION_ID, LOCATION_KWARGS, MALWARE_ID, MALWARE_KWARGS, RELATIONSHIP_IDS,
    REPORT_ID, REPORT_KWARGS, THREAT_ACTOR_ID, THREAT_ACTOR_KWARGS, TOOL_ID,
    TOOL_KWARGS, VULNERABILITY_ID, VULNERABILITY_KWARGS,
)

FS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "stix2_data")


@pytest.fixture
def ds():
    cam = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    mal = stix2.v21.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    rel1 = stix2.v21.Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = stix2.v21.Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = stix2.v21.Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    reprt = stix2.v21.Report(
        name="Malware Report", published="2021-05-09T08:22:22Z",
        object_refs=[mal.id, rel1.id, ind.id],
    )
    stix_objs = [cam, idy, ind, mal, rel1, rel2, rel3, reprt]
    yield stix2.MemoryStore(stix_objs)


@pytest.fixture
def ds2_objects():
    cam = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = stix2.v21.Indicator(id=INDICATOR_ID, created_by_ref=idy.id, **INDICATOR_KWARGS)
    indv2 = ind.new_version(
        external_references=[
            {
                "source_name": "unknown",
                "url": "https://examplewebsite.com/",
            },
        ],
        object_marking_refs=[stix2.v21.TLP_WHITE],
    )
    mal = stix2.v21.Malware(id=MALWARE_ID, created_by_ref=idy.id, **MALWARE_KWARGS)
    malv2 = mal.new_version(
        external_references=[
            {
                "source_name": "unknown",
                "url": "https://examplewebsite2.com/",
            },
        ],
    )
    rel1 = stix2.v21.Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = stix2.v21.Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = stix2.v21.Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    stix_objs = [cam, idy, ind, indv2, mal, malv2, rel1, rel2, rel3]
    reprt = stix2.v21.Report(
        created_by_ref=idy.id, name="example",
        published="2021-04-09T08:22:22Z", object_refs=stix_objs,
    )
    stix_objs.append(reprt)
    yield stix_objs


@pytest.fixture
def ds2(ds2_objects):
    yield stix2.MemoryStore(ds2_objects)


@pytest.fixture
def fs():
    yield stix2.FileSystemSource(FS_PATH)


def test_object_factory_created_by_ref_str():
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID)
    ind = factory.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID


def test_object_factory_created_by_ref_obj():
    id_obj = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=id_obj)
    ind = factory.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID


def test_object_factory_override_default():
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID)
    new_id = "identity--983b3172-44fe-4a80-8091-eb8098841fe8"
    ind = factory.create(stix2.v21.Indicator, created_by_ref=new_id, **INDICATOR_KWARGS)
    assert ind.created_by_ref == new_id


def test_object_factory_created():
    factory = stix2.ObjectFactory(created=FAKE_TIME)
    ind = factory.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    assert ind.created == FAKE_TIME
    assert ind.modified == FAKE_TIME


def test_object_factory_external_reference():
    ext_ref = stix2.v21.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
    )
    factory = stix2.ObjectFactory(external_references=ext_ref)
    ind = factory.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    assert ind.external_references[0].source_name == "ACME Threat Intel"
    assert ind.external_references[0].description == "Threat report"

    ind2 = factory.create(stix2.v21.Indicator, external_references=None, **INDICATOR_KWARGS)
    assert 'external_references' not in ind2


def test_object_factory_obj_markings():
    stmt_marking = stix2.v21.StatementMarking("Copyright 2016, Example Corp")
    mark_def = stix2.v21.MarkingDefinition(
        definition_type="statement",
        definition=stmt_marking,
    )
    factory = stix2.ObjectFactory(object_marking_refs=[mark_def, stix2.v21.TLP_AMBER])
    ind = factory.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    assert mark_def.id in ind.object_marking_refs
    assert stix2.v21.TLP_AMBER.id in ind.object_marking_refs

    factory = stix2.ObjectFactory(object_marking_refs=stix2.v21.TLP_RED)
    ind = factory.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    assert stix2.v21.TLP_RED.id in ind.object_marking_refs


def test_object_factory_list_append():
    ext_ref = stix2.v21.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report from ACME",
    )
    ext_ref2 = stix2.v21.ExternalReference(
        source_name="Yet Another Threat Report",
        description="Threat report from YATR",
    )
    ext_ref3 = stix2.v21.ExternalReference(
        source_name="Threat Report #3",
        description="One more threat report",
    )
    factory = stix2.ObjectFactory(external_references=ext_ref)
    ind = factory.create(stix2.v21.Indicator, external_references=ext_ref2, **INDICATOR_KWARGS)
    assert ind.external_references[1].source_name == "Yet Another Threat Report"

    ind = factory.create(stix2.v21.Indicator, external_references=[ext_ref2, ext_ref3], **INDICATOR_KWARGS)
    assert ind.external_references[2].source_name == "Threat Report #3"


def test_object_factory_list_replace():
    ext_ref = stix2.v21.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report from ACME",
    )
    ext_ref2 = stix2.v21.ExternalReference(
        source_name="Yet Another Threat Report",
        description="Threat report from YATR",
    )
    factory = stix2.ObjectFactory(external_references=ext_ref, list_append=False)
    ind = factory.create(stix2.v21.Indicator, external_references=ext_ref2, **INDICATOR_KWARGS)
    assert len(ind.external_references) == 1
    assert ind.external_references[0].source_name == "Yet Another Threat Report"


def test_environment_functions():
    env = stix2.Environment(
        stix2.ObjectFactory(created_by_ref=IDENTITY_ID),
        stix2.MemoryStore(),
    )

    # Create a STIX object
    ind = env.create(stix2.v21.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
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
    ind = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    env = stix2.Environment(source=stix2.MemorySource([ind]), sink=stix2.MemorySink([ind]))
    assert env.get(INDICATOR_ID).indicator_types[0] == 'malicious-activity'


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
        env.add(stix2.v21.Indicator(**INDICATOR_KWARGS))
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
    ind = env.create(stix2.v21.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    assert ind.id == INDICATOR_ID


def test_parse_malware():
    env = stix2.Environment()
    data = """{
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        "created": "2017-01-01T12:34:56.000Z",
        "modified": "2017-01-01T12:34:56.000Z",
        "name": "Cryptolocker",
        "malware_types": [
            "ransomware"
        ],
        "is_family": false
    }"""
    mal = env.parse(data, version="2.1")

    assert mal.type == 'malware'
    assert mal.spec_version == '2.1'
    assert mal.id == MALWARE_ID
    assert mal.created == FAKE_TIME
    assert mal.modified == FAKE_TIME
    assert mal.malware_types == ['ransomware']
    assert mal.name == "Cryptolocker"
    assert not mal.is_family


def test_creator_of():
    identity = stix2.v21.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(store=stix2.MemoryStore(), factory=factory)
    env.add(identity)

    ind = env.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is identity


def test_creator_of_no_datasource():
    identity = stix2.v21.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(factory=factory)

    ind = env.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    with pytest.raises(AttributeError) as excinfo:
        env.creator_of(ind)
    assert 'Environment has no data source' in str(excinfo.value)


def test_creator_of_not_found():
    identity = stix2.v21.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(store=stix2.MemoryStore(), factory=factory)

    ind = env.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is None


def test_creator_of_no_created_by_ref():
    env = stix2.Environment(store=stix2.MemoryStore())
    ind = env.create(stix2.v21.Indicator, **INDICATOR_KWARGS)
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
        "is_family": False,
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


def test_object_similarity_on_same_attack_pattern1():
    ap1 = stix2.v21.AttackPattern(id=ATTACK_PATTERN_ID, **ATTACK_PATTERN_KWARGS)
    ap2 = stix2.v21.AttackPattern(id=ATTACK_PATTERN_ID, **ATTACK_PATTERN_KWARGS)
    env = stix2.Environment().object_similarity(ap1, ap2)
    assert round(env) == 100


def test_object_similarity_on_same_attack_pattern2():
    ATTACK_KWARGS = dict(
        name="Phishing",
        external_references=[
            {
                "url": "https://example2",
                "source_name": "some-source2",
            },
        ],
    )
    ap1 = stix2.v21.AttackPattern(id=ATTACK_PATTERN_ID, **ATTACK_KWARGS)
    ap2 = stix2.v21.AttackPattern(id=ATTACK_PATTERN_ID, **ATTACK_KWARGS)
    env = stix2.Environment().object_similarity(ap1, ap2)
    assert round(env) == 100


def test_object_similarity_on_same_campaign1():
    camp1 = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    camp2 = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    env = stix2.Environment().object_similarity(camp1, camp2)
    assert round(env) == 100


def test_object_similarity_on_same_campaign2():
    CAMP_KWARGS = dict(
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector.",
        aliases=["super-green", "some-green"],
    )
    camp1 = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMP_KWARGS)
    camp2 = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMP_KWARGS)
    env = stix2.Environment().object_similarity(camp1, camp2)
    assert round(env) == 100


def test_object_similarity_on_same_identity1():
    iden1 = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    iden2 = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    env = stix2.Environment().object_similarity(iden1, iden2)
    assert round(env) == 100


def test_object_similarity_on_same_identity2():
    IDEN_KWARGS = dict(
        name="John Smith",
        identity_class="individual",
        sectors=["government", "infrastructure"],
    )
    iden1 = stix2.v21.Identity(id=IDENTITY_ID, **IDEN_KWARGS)
    iden2 = stix2.v21.Identity(id=IDENTITY_ID, **IDEN_KWARGS)
    env = stix2.Environment().object_similarity(iden1, iden2)
    assert round(env) == 100


def test_object_similarity_on_same_indicator():
    ind1 = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    ind2 = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    env = stix2.Environment().object_similarity(ind1, ind2)
    assert round(env) == 100


def test_object_similarity_on_same_location1():
    location_kwargs = dict(latitude=45, longitude=179)
    loc1 = stix2.v21.Location(id=LOCATION_ID, **location_kwargs)
    loc2 = stix2.v21.Location(id=LOCATION_ID, **location_kwargs)
    env = stix2.Environment().object_similarity(loc1, loc2)
    assert round(env) == 100


def test_object_similarity_on_same_location2():
    location_kwargs = dict(
        latitude=38.889,
        longitude=-77.023,
        region="northern-america",
        country="us",
    )
    loc1 = stix2.v21.Location(id=LOCATION_ID, **location_kwargs)
    loc2 = stix2.v21.Location(id=LOCATION_ID, **location_kwargs)
    env = stix2.Environment().object_similarity(loc1, loc2)
    assert round(env) == 100


def test_object_similarity_location_with_no_latlong():
    loc_kwargs = dict(country="US", administrative_area="US-DC")
    loc1 = stix2.v21.Location(id=LOCATION_ID, **LOCATION_KWARGS)
    loc2 = stix2.v21.Location(id=LOCATION_ID, **loc_kwargs)
    env = stix2.Environment().object_similarity(loc1, loc2)
    assert round(env) != 100


def test_object_similarity_on_same_malware():
    malw1 = stix2.v21.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    malw2 = stix2.v21.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    env = stix2.Environment().object_similarity(malw1, malw2)
    assert round(env) == 100


def test_object_similarity_on_same_threat_actor1():
    ta1 = stix2.v21.ThreatActor(id=THREAT_ACTOR_ID, **THREAT_ACTOR_KWARGS)
    ta2 = stix2.v21.ThreatActor(id=THREAT_ACTOR_ID, **THREAT_ACTOR_KWARGS)
    env = stix2.Environment().object_similarity(ta1, ta2)
    assert round(env) == 100


def test_object_similarity_on_same_threat_actor2():
    THREAT_KWARGS = dict(
        threat_actor_types=["crime-syndicate"],
        aliases=["super-evil"],
        name="Evil Org",
    )
    ta1 = stix2.v21.ThreatActor(id=THREAT_ACTOR_ID, **THREAT_KWARGS)
    ta2 = stix2.v21.ThreatActor(id=THREAT_ACTOR_ID, **THREAT_KWARGS)
    env = stix2.Environment().object_similarity(ta1, ta2)
    assert round(env) == 100


def test_object_similarity_on_same_tool():
    tool1 = stix2.v21.Tool(id=TOOL_ID, **TOOL_KWARGS)
    tool2 = stix2.v21.Tool(id=TOOL_ID, **TOOL_KWARGS)
    env = stix2.Environment().object_similarity(tool1, tool2)
    assert round(env) == 100


def test_object_similarity_on_same_vulnerability1():
    vul1 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
    vul2 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
    prop_scores = {}
    env = stix2.Environment().object_similarity(vul1, vul2, prop_scores)
    assert round(env) == 100
    assert round(prop_scores["matching_score"]) == 30
    assert round(prop_scores["sum_weights"]) == 30


def test_object_equivalence_on_same_vulnerability1():
    vul1 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
    vul2 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
    prop_scores = {}
    env = stix2.Environment().object_equivalence(vul1, vul2, prop_scores)
    assert env is True
    assert round(prop_scores["matching_score"]) == 30
    assert round(prop_scores["sum_weights"]) == 30


def test_object_similarity_on_same_vulnerability2():
    VULN_KWARGS1 = dict(
        name="Heartbleed",
        external_references=[
            {
                "url": "https://example",
                "source_name": "some-source",
            },
        ],
    )
    VULN_KWARGS2 = dict(
        name="Foo",
        external_references=[
            {
                "url": "https://example2",
                "source_name": "some-source2",
            },
        ],
    )
    vul1 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULN_KWARGS1)
    vul2 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULN_KWARGS2)
    prop_scores = {}
    env = stix2.Environment().object_similarity(vul1, vul2, prop_scores)
    assert round(env) == 0.0
    assert round(prop_scores["matching_score"]) == 0
    assert round(prop_scores["sum_weights"]) == 100


def test_object_equivalence_on_same_vulnerability2():
    VULN_KWARGS1 = dict(
        name="Heartbleed",
        external_references=[
            {
                "url": "https://example",
                "source_name": "some-source",
            },
        ],
    )
    VULN_KWARGS2 = dict(
        name="Foo",
        external_references=[
            {
                "url": "https://example2",
                "source_name": "some-source2",
            },
        ],
    )
    vul1 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULN_KWARGS1)
    vul2 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULN_KWARGS2)
    prop_scores = {}
    env = stix2.Environment().object_equivalence(vul1, vul2, prop_scores)
    assert env is False
    assert round(prop_scores["matching_score"]) == 0
    assert round(prop_scores["sum_weights"]) == 100


def test_object_similarity_on_unknown_object():
    CUSTOM_KWARGS1 = dict(
        type="x-foobar",
        id="x-foobar--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        name="Heartbleed",
        external_references=[
            {
                "url": "https://example",
                "source_name": "some-source",
            },
        ],
    )
    CUSTOM_KWARGS2 = dict(
        type="x-foobar",
        id="x-foobar--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        name="Foo",
        external_references=[
            {
                "url": "https://example2",
                "source_name": "some-source2",
            },
        ],
    )

    def _x_foobar_checks(obj1, obj2, **weights):
        matching_score = 0.0
        sum_weights = 0.0
        if stix2.equivalence.object.check_property_present("external_references", obj1, obj2):
            w = weights["external_references"]
            sum_weights += w
            matching_score += w * stix2.equivalence.object.partial_external_reference_based(
                obj1["external_references"],
                obj2["external_references"],
            )
        if stix2.equivalence.object.check_property_present("name", obj1, obj2):
            w = weights["name"]
            sum_weights += w
            matching_score += w * stix2.equivalence.object.partial_string_based(obj1["name"], obj2["name"])
        return matching_score, sum_weights

    weights = {
        "x-foobar": {
            "external_references": 40,
            "name": 60,
            "method": _x_foobar_checks,
        },
        "_internal": {
            "ignore_spec_version": False,
        },
    }
    cust1 = stix2.parse(CUSTOM_KWARGS1, allow_custom=True)
    cust2 = stix2.parse(CUSTOM_KWARGS2, allow_custom=True)
    env = stix2.Environment().object_similarity(cust1, cust2, **weights)
    assert round(env) == 0


def test_object_similarity_different_type_raises():
    with pytest.raises(ValueError) as excinfo:
        vul1 = stix2.v21.Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
        ind1 = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
        stix2.Environment().object_similarity(vul1, ind1)

    assert str(excinfo.value) == "The objects to compare must be of the same type!"


def test_object_similarity_different_spec_version_raises():
    with pytest.raises(ValueError) as excinfo:
        V20_KWARGS = dict(
            labels=['malicious-activity'],
            pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        )
        ind1 = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
        ind2 = stix2.v20.Indicator(id=INDICATOR_ID, **V20_KWARGS)
        stix2.Environment().object_similarity(ind1, ind2)

    assert str(excinfo.value) == "The objects to compare must be of the same spec version!"


def test_object_similarity_zero_match():
    IND_KWARGS = dict(
        indicator_types=["anomalous-activity"],
        pattern="[ipv4-addr:value = '192.168.1.1']",
        pattern_type="stix",
        valid_from="2019-01-01T12:34:56Z",
        labels=["APTX", "foo"],
    )
    weights = {
        "indicator": {
            "indicator_types": (15, stix2.equivalence.object.partial_list_based),
            "pattern": (80, stix2.equivalence.object.custom_pattern_based),
            "valid_from": (5, stix2.equivalence.object.partial_timestamp_based),
            "tdelta": 1,  # One day interval
        },
        "_internal": {
            "ignore_spec_version": False,
        },
    }
    ind1 = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    ind2 = stix2.v21.Indicator(id=INDICATOR_ID, **IND_KWARGS)
    env = stix2.Environment().object_similarity(ind1, ind2, **weights)
    assert round(env) == 0
    env = stix2.Environment().object_similarity(ind2, ind1, **weights)
    assert round(env) == 0


def test_object_similarity_different_spec_version():
    IND_KWARGS = dict(
        labels=["malicious-activity"],
        pattern="[ipv4-addr:value = '192.168.1.1']",
    )
    weights = {
        "indicator": {
            "indicator_types": (15, stix2.equivalence.object.partial_list_based),
            "pattern": (80, stix2.equivalence.object.custom_pattern_based),
            "valid_from": (5, stix2.equivalence.object.partial_timestamp_based),
            "tdelta": 1,  # One day interval
        },
    }
    ind1 = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    ind2 = stix2.v20.Indicator(id=INDICATOR_ID, **IND_KWARGS)
    env = stix2.Environment().object_similarity(ind1, ind2, ignore_spec_version=True, **weights)
    assert round(env) == 0

    env = stix2.Environment().object_similarity(ind2, ind1, ignore_spec_version=True, **weights)
    assert round(env) == 0


@pytest.mark.parametrize(
    "refs1,refs2,ret_val", [
        (
            [
                {
                    "url": "https://attack.mitre.org/techniques/T1150",
                    "source_name": "mitre-attack",
                    "external_id": "T1150",
                },
                {
                    "url": "https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/",
                    "source_name": "Sofacy Komplex Trojan",
                    "description": "Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.",
                },
            ],
            [
                {
                    "url": "https://attack.mitre.org/techniques/T1129",
                    "source_name": "mitre-attack",
                    "external_id": "T1129",
                },
                {
                    "url": "https://en.wikipedia.org/wiki/Microsoft_Windows_library_files",
                    "source_name": "Wikipedia Windows Library Files",
                    "description": "Wikipedia. (2017, January 31). Microsoft Windows library files. Retrieved February 13, 2017.",
                },
            ],
            0.0,
        ),
        (
            [
                {
                    "url": "https://attack.mitre.org/techniques/T1129",
                    "source_name": "mitre-attack",
                    "external_id": "T1129",
                },
            ],
            [
                {
                    "url": "https://attack.mitre.org/techniques/T1129",
                    "source_name": "mitre-attack",
                    "external_id": "T1129",
                },
                {
                    "url": "https://en.wikipedia.org/wiki/Microsoft_Windows_library_files",
                    "source_name": "Wikipedia Windows Library Files",
                    "description": "Wikipedia. (2017, January 31). Microsoft Windows library files. Retrieved February 13, 2017.",
                },
            ],
            1.0,
        ),
        (
            [
                {
                    "url": "https://example",
                    "source_name": "some-source",
                },
            ],
            [
                {
                    "url": "https://example",
                    "source_name": "some-source",
                },
            ],
            1.0,
        ),
    ],
)
def test_object_similarity_external_references(refs1, refs2, ret_val):
    value = stix2.equivalence.object.partial_external_reference_based(refs1, refs2)
    assert value == ret_val


def test_object_similarity_timestamp():
    t1 = "2018-10-17T00:14:20.652Z"
    t2 = "2018-10-17T12:14:20.652Z"
    assert stix2.equivalence.object.partial_timestamp_based(t1, t2, 1) == 0.5


def test_object_similarity_exact_match():
    t1 = "2018-10-17T00:14:20.652Z"
    t2 = "2018-10-17T12:14:20.652Z"
    assert stix2.equivalence.object.exact_match(t1, t2) == 0.0


def test_no_datastore_fallsback_list_based_check_for_refs_check():
    r1 = stix2.v21.Report(id=REPORT_ID, **REPORT_KWARGS)
    r2 = stix2.v21.Report(id=REPORT_ID, **REPORT_KWARGS)
    prop_scores = {}
    assert stix2.Environment().object_similarity(r1, r2, prop_scores) == 100.0
    assert prop_scores["object_refs"]["check_type"] == "partial_list_based"


def custom_semantic_equivalence_method(obj1, obj2, **weights):
    return 96.0, 100.0


def test_object_similarity_method_provided():
    # Because `method` is provided, `partial_list_based` will be ignored
    TOOL2_KWARGS = dict(
        name="Random Software",
        tool_types=["information-gathering"],
    )

    weights = {
        "tool": {
            "tool_types": (20, stix2.equivalence.object.partial_list_based),
            "name": (80, stix2.equivalence.object.partial_string_based),
            "method": custom_semantic_equivalence_method,
        },
    }

    tool1 = stix2.v21.Tool(id=TOOL_ID, **TOOL_KWARGS)
    tool2 = stix2.v21.Tool(id=TOOL_ID, **TOOL2_KWARGS)
    env = stix2.Environment().object_similarity(tool1, tool2, **weights)
    assert round(env) == 96


def test_object_similarity_prop_scores():
    TOOL2_KWARGS = dict(
        name="Random Software",
        tool_types=["information-gathering"],
    )

    prop_scores = {}

    tool1 = stix2.v21.Tool(id=TOOL_ID, **TOOL_KWARGS)
    tool2 = stix2.v21.Tool(id=TOOL_ID, **TOOL2_KWARGS)
    stix2.Environment().object_similarity(tool1, tool2, prop_scores)
    assert len(prop_scores) == 4
    assert round(prop_scores["matching_score"], 1) == 8.9
    assert round(prop_scores["sum_weights"], 1) == 100.0


def custom_semantic_equivalence_method_prop_scores(obj1, obj2, prop_scores, **weights):
    prop_scores["matching_score"] = 96.0
    prop_scores["sum_weights"] = 100.0
    return 96.0, 100.0


def test_object_similarity_prop_scores_method_provided():
    TOOL2_KWARGS = dict(
        name="Random Software",
        tool_types=["information-gathering"],
    )

    weights = {
        "tool": {
            "tool_types": 20,
            "name": 80,
            "method": custom_semantic_equivalence_method_prop_scores,
        },
    }

    prop_scores = {}

    tool1 = stix2.v21.Tool(id=TOOL_ID, **TOOL_KWARGS)
    tool2 = stix2.v21.Tool(id=TOOL_ID, **TOOL2_KWARGS)
    env = stix2.Environment().object_similarity(tool1, tool2, prop_scores, **weights)
    assert round(env) == 96
    assert len(prop_scores) == 2
    assert prop_scores["matching_score"] == 96.0
    assert prop_scores["sum_weights"] == 100.0


def test_versioned_checks(ds, ds2):
    # Testing internal method
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
    ind = stix2.v21.Indicator(
        **dict(
            indicator_types=["malicious-activity"],
            pattern_type="stix",
            pattern="[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
            valid_from="2017-01-01T12:34:56Z",
            external_references=[
                {
                  "source_name": "unknown",
                  "url": "https://examplewebsite2.com/",
                },
            ],
            object_marking_refs=[stix2.v21.TLP_WHITE],
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
            "ds1": ds,
            "ds2": ds2,
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

    score = stix2.equivalence.object.list_reference_check(
        object_refs2,
        object_refs1,
        ds2,
        ds,
        **weights,
    )
    assert round(score) == 1


def test_graph_similarity_raises_value_error(ds):
    with pytest.raises(ValueError):
        prop_scores1 = {}
        stix2.Environment().graph_similarity(ds, ds2, prop_scores1, max_depth=-1)


def test_graph_similarity_with_filesystem_source(ds, fs):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_similarity(
        fs, ds, prop_scores1,
        ignore_spec_version=True,
        versioning_checks=False,
        max_depth=1,
    )

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_similarity(
        ds, fs, prop_scores2,
        ignore_spec_version=True,
        versioning_checks=False,
        max_depth=1,
    )

    assert round(env1) == 23
    assert round(prop_scores1["matching_score"]) == 411
    assert round(prop_scores1["len_pairs"]) == 18

    assert round(env2) == 23
    assert round(prop_scores2["matching_score"]) == 411
    assert round(prop_scores2["len_pairs"]) == 18

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_depth_limiting():
    g1 = [
        {
            "type": "foo",
            "id": "foo--07f9dd2a-1cce-45bb-8cbe-dba3f007aafd",
            "spec_version": "2.1",
            "created": "1986-02-08T00:20:17Z",
            "modified": "1989-12-11T06:54:29Z",
            "some1_ref": "foo--700a8a3c-9936-412f-b4eb-ede466476180",
            "some2_ref": "foo--f4a999a3-df94-499d-9cac-6c02e21775ee",
        },
        {
            "type": "foo",
            "id": "foo--700a8a3c-9936-412f-b4eb-ede466476180",
            "spec_version": "2.1",
            "created": "1989-01-06T10:31:54Z",
            "modified": "1995-06-18T10:25:01Z",
            "some1_ref": "foo--705afd45-eb56-43fc-a214-313d63d199a3",
        },
        {
            "type": "foo",
            "id": "foo--705afd45-eb56-43fc-a214-313d63d199a3",
            "spec_version": "2.1",
            "created": "1977-11-06T21:19:29Z",
            "modified": "1997-12-02T20:33:34Z",
        },
        {
            "type": "foo",
            "id": "foo--f4a999a3-df94-499d-9cac-6c02e21775ee",
            "spec_version": "2.1",
            "created": "1991-09-17T00:40:52Z",
            "modified": "1992-12-06T11:02:47Z",
            "name": "alice",
        },
    ]

    g2 = [
        {
            "type": "foo",
            "id": "foo--71570479-3e6e-48d2-81fb-897454dec55d",
            "spec_version": "2.1",
            "created": "1975-12-22T05:20:38Z",
            "modified": "1980-11-11T01:09:03Z",
            "some1_ref": "foo--4aeda39b-31fa-4ffb-a847-d8edc175a579",
            "some2_ref": "foo--941e48d6-3100-4419-9e8c-cf1eb59e71b2",
        },
        {
            "type": "foo",
            "id": "foo--4aeda39b-31fa-4ffb-a847-d8edc175a579",
            "spec_version": "2.1",
            "created": "1976-01-05T08:32:03Z",
            "modified": "1980-11-09T05:41:02Z",
            "some1_ref": "foo--689252c3-5d20-43ff-bbf7-c8e45d713768",
        },
        {
            "type": "foo",
            "id": "foo--689252c3-5d20-43ff-bbf7-c8e45d713768",
            "spec_version": "2.1",
            "created": "1974-09-11T18:56:30Z",
            "modified": "1976-10-31T11:59:43Z",
        },
        {
            "type": "foo",
            "id": "foo--941e48d6-3100-4419-9e8c-cf1eb59e71b2",
            "spec_version": "2.1",
            "created": "1985-01-03T01:07:03Z",
            "modified": "1992-07-20T21:32:31Z",
            "name": "alice",
        },
    ]

    mem_store1 = stix2.MemorySource(g1)
    mem_store2 = stix2.MemorySource(g2)

    custom_weights = {
        "foo": {
            "some1_ref": (33, stix2.equivalence.object.reference_check),
            "some2_ref": (33, stix2.equivalence.object.reference_check),
            "name": (34, stix2.equivalence.object.partial_string_based),
        },
    }
    prop_scores1 = {}
    env1 = stix2.equivalence.graph.graph_similarity(
        mem_store1, mem_store2, prop_scores1, **custom_weights
    )

    assert round(env1) == 38
    assert round(prop_scores1["matching_score"]) == 300
    assert round(prop_scores1["len_pairs"]) == 8
    # from 'alice' check in de-reference
    assert prop_scores1['summary']['foo--71570479-3e6e-48d2-81fb-897454dec55d']['prop_score']['some2_ref']['weight'] == 33
    assert prop_scores1['summary']['foo--07f9dd2a-1cce-45bb-8cbe-dba3f007aafd']['prop_score']['some2_ref']['weight'] == 33

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.equivalence.graph.graph_similarity(
        mem_store2, mem_store1, prop_scores2, **custom_weights
    )

    assert round(env2) == 38
    assert round(prop_scores2["matching_score"]) == 300
    assert round(prop_scores2["len_pairs"]) == 8
    # from 'alice' check in de-reference
    assert prop_scores2['summary']['foo--71570479-3e6e-48d2-81fb-897454dec55d']['prop_score']['some2_ref']['weight'] == 33
    assert prop_scores2['summary']['foo--07f9dd2a-1cce-45bb-8cbe-dba3f007aafd']['prop_score']['some2_ref']['weight'] == 33


def test_graph_similarity_with_duplicate_graph(ds):
    prop_scores = {}
    env = stix2.Environment().graph_similarity(ds, ds, prop_scores)
    assert round(env) == 100
    assert round(prop_scores["matching_score"]) == 800
    assert round(prop_scores["len_pairs"]) == 8


def test_graph_similarity_with_versioning_check_on(ds2, ds):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_similarity(ds, ds2, prop_scores1, versioning_checks=True)
    assert round(env1) == 88
    assert round(prop_scores1["matching_score"]) == 789
    assert round(prop_scores1["len_pairs"]) == 9

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_similarity(ds2, ds, prop_scores2, versioning_checks=True)
    assert round(env2) == 88
    assert round(prop_scores2["matching_score"]) == 789
    assert round(prop_scores2["len_pairs"]) == 9

    prop_scores1["matching_score"] = round(prop_scores1["matching_score"], 3)
    prop_scores2["matching_score"] = round(prop_scores2["matching_score"], 3)
    assert json.dumps(prop_scores1, sort_keys=True, indent=4) == json.dumps(prop_scores2, sort_keys=True, indent=4)


def test_graph_similarity_with_versioning_check_off(ds2, ds):
    prop_scores1 = {}
    env1 = stix2.Environment().graph_similarity(ds, ds2, prop_scores1)
    assert round(env1) == 88
    assert round(prop_scores1["matching_score"]) == 789
    assert round(prop_scores1["len_pairs"]) == 9

    # Switching parameters
    prop_scores2 = {}
    env2 = stix2.Environment().graph_similarity(ds2, ds, prop_scores2)
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
    assert round(prop_scores1["matching_score"]) == 411
    assert round(prop_scores1["len_pairs"]) == 18

    assert env2 is False
    assert round(prop_scores2["matching_score"]) == 411
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
