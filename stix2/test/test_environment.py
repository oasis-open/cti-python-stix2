import pytest

import stix2

from .constants import (FAKE_TIME, IDENTITY_ID, IDENTITY_KWARGS, INDICATOR_ID,
                        INDICATOR_KWARGS, MALWARE_ID)


def test_object_factory_created_by_ref_str():
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID)
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID


def test_object_factory_created_by_ref_obj():
    id_obj = stix2.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=id_obj)
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID


def test_object_factory_override_default():
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID)
    new_id = "identity--983b3172-44fe-4a80-8091-eb8098841fe8"
    ind = factory.create(stix2.Indicator, created_by_ref=new_id, **INDICATOR_KWARGS)
    assert ind.created_by_ref == new_id


def test_object_factory_created():
    factory = stix2.ObjectFactory(created=FAKE_TIME)
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert ind.created == FAKE_TIME
    assert ind.modified == FAKE_TIME


def test_object_factory_external_resource():
    ext_ref = stix2.ExternalReference(source_name="ACME Threat Intel",
                                      description="Threat report")
    factory = stix2.ObjectFactory(external_references=ext_ref)
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert ind.external_references[0].source_name == "ACME Threat Intel"
    assert ind.external_references[0].description == "Threat report"

    ind2 = factory.create(stix2.Indicator, external_references=None, **INDICATOR_KWARGS)
    assert 'external_references' not in ind2


def test_object_factory_obj_markings():
    stmt_marking = stix2.StatementMarking("Copyright 2016, Example Corp")
    mark_def = stix2.MarkingDefinition(definition_type="statement",
                                       definition=stmt_marking)
    factory = stix2.ObjectFactory(object_marking_refs=[mark_def, stix2.TLP_AMBER])
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert mark_def.id in ind.object_marking_refs
    assert stix2.TLP_AMBER.id in ind.object_marking_refs

    factory = stix2.ObjectFactory(object_marking_refs=stix2.TLP_RED)
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert stix2.TLP_RED.id in ind.object_marking_refs


def test_object_factory_list_append():
    ext_ref = stix2.ExternalReference(source_name="ACME Threat Intel",
                                      description="Threat report from ACME")
    ext_ref2 = stix2.ExternalReference(source_name="Yet Another Threat Report",
                                       description="Threat report from YATR")
    ext_ref3 = stix2.ExternalReference(source_name="Threat Report #3",
                                       description="One more threat report")
    factory = stix2.ObjectFactory(external_references=ext_ref)
    ind = factory.create(stix2.Indicator, external_references=ext_ref2, **INDICATOR_KWARGS)
    assert ind.external_references[1].source_name == "Yet Another Threat Report"

    ind = factory.create(stix2.Indicator, external_references=[ext_ref2, ext_ref3], **INDICATOR_KWARGS)
    assert ind.external_references[2].source_name == "Threat Report #3"


def test_object_factory_list_replace():
    ext_ref = stix2.ExternalReference(source_name="ACME Threat Intel",
                                      description="Threat report from ACME")
    ext_ref2 = stix2.ExternalReference(source_name="Yet Another Threat Report",
                                       description="Threat report from YATR")
    factory = stix2.ObjectFactory(external_references=ext_ref, list_append=False)
    ind = factory.create(stix2.Indicator, external_references=ext_ref2, **INDICATOR_KWARGS)
    assert len(ind.external_references) == 1
    assert ind.external_references[0].source_name == "Yet Another Threat Report"


def test_environment_functions():
    env = stix2.Environment(stix2.ObjectFactory(created_by_ref=IDENTITY_ID),
                            stix2.MemoryStore())

    # Create a STIX object
    ind = env.create(stix2.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    assert ind.created_by_ref == IDENTITY_ID

    # Add objects to datastore
    ind2 = ind.new_version(labels=['benign'])
    env.add([ind, ind2])

    # Get both versions of the object
    resp = env.all_versions(INDICATOR_ID)
    assert len(resp) == 1  # should be 2, but MemoryStore only keeps 1 version of objects

    # Get just the most recent version of the object
    resp = env.get(INDICATOR_ID)
    assert resp['labels'][0] == 'benign'

    # Search on something other than id
    query = [stix2.Filter('type', '=', 'vulnerability')]
    resp = env.query(query)
    assert len(resp) == 0

    # See different results after adding filters to the environment
    env.add_filters([stix2.Filter('type', '=', 'indicator'),
                    stix2.Filter('created_by_ref', '=', IDENTITY_ID)])
    env.add_filter(stix2.Filter('labels', '=', 'benign'))  # should be 'malicious-activity'
    resp = env.get(INDICATOR_ID)
    assert resp['labels'][0] == 'benign'  # should be 'malicious-activity'


def test_environment_source_and_sink():
    ind = stix2.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    env = stix2.Environment(source=stix2.MemorySource([ind]), sink=stix2.MemorySink([ind]))
    assert env.get(INDICATOR_ID).labels[0] == 'malicious-activity'


def test_environment_datastore_and_sink():
    with pytest.raises(ValueError) as excinfo:
        stix2.Environment(factory=stix2.ObjectFactory(),
                          store=stix2.MemoryStore(), sink=stix2.MemorySink)
    assert 'Data store already provided' in str(excinfo.value)


def test_environment_no_datastore():
    env = stix2.Environment(factory=stix2.ObjectFactory())

    with pytest.raises(AttributeError) as excinfo:
        env.add(stix2.Indicator(**INDICATOR_KWARGS))
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


def test_environment_add_filters():
    env = stix2.Environment(factory=stix2.ObjectFactory())
    env.add_filters([INDICATOR_ID])
    env.add_filter(INDICATOR_ID)


def test_environment_datastore_and_no_object_factory():
    # Uses a default object factory
    env = stix2.Environment(store=stix2.MemoryStore())
    ind = env.create(stix2.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    assert ind.id == INDICATOR_ID


def test_parse_malware():
    env = stix2.Environment()
    data = """{
        "type": "malware",
        "id": "malware--fedcba98-7654-3210-fedc-ba9876543210",
        "created": "2017-01-01T12:34:56.000Z",
        "modified": "2017-01-01T12:34:56.000Z",
        "name": "Cryptolocker",
        "labels": [
            "ransomware"
        ]
    }"""
    mal = env.parse(data)

    assert mal.type == 'malware'
    assert mal.id == MALWARE_ID
    assert mal.created == FAKE_TIME
    assert mal.modified == FAKE_TIME
    assert mal.labels == ['ransomware']
    assert mal.name == "Cryptolocker"


def test_created_by():
    identity = stix2.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(store=stix2.MemoryStore(), factory=factory)
    env.add(identity)

    ind = env.create(stix2.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is identity


def test_created_by_no_datasource():
    identity = stix2.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(factory=factory)

    ind = env.create(stix2.Indicator, **INDICATOR_KWARGS)
    with pytest.raises(AttributeError) as excinfo:
        env.creator_of(ind)
    assert 'Environment has no data source' in str(excinfo.value)


def test_created_by_not_found():
    identity = stix2.Identity(**IDENTITY_KWARGS)
    factory = stix2.ObjectFactory(created_by_ref=identity.id)
    env = stix2.Environment(store=stix2.MemoryStore(), factory=factory)

    ind = env.create(stix2.Indicator, **INDICATOR_KWARGS)
    creator = env.creator_of(ind)
    assert creator is None
