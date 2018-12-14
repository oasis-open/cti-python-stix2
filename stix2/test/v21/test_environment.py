import pytest

import stix2

from .constants import (
    CAMPAIGN_ID, CAMPAIGN_KWARGS, FAKE_TIME, IDENTITY_ID, IDENTITY_KWARGS,
    INDICATOR_ID, INDICATOR_KWARGS, MALWARE_ID, MALWARE_KWARGS,
    RELATIONSHIP_IDS,
)


@pytest.fixture
def ds():
    cam = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    mal = stix2.v21.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    rel1 = stix2.v21.Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = stix2.v21.Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = stix2.v21.Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    stix_objs = [cam, idy, ind, mal, rel1, rel2, rel3]
    yield stix2.MemoryStore(stix_objs)


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
        ]
    }"""
    mal = env.parse(data, version="2.1")

    assert mal.type == 'malware'
    assert mal.spec_version == '2.1'
    assert mal.id == MALWARE_ID
    assert mal.created == FAKE_TIME
    assert mal.modified == FAKE_TIME
    assert mal.malware_types == ['ransomware']
    assert mal.name == "Cryptolocker"


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
