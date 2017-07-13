import stix2

from .constants import (FAKE_TIME, IDENTITY_ID, IDENTITY_KWARGS,
                        INDICATOR_KWARGS)


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


def test_object_factory_granular_markings():
    marking = stix2.GranularMarking(marking_ref=stix2.TLP_AMBER,
                                    selectors="created_by_ref")
    factory = stix2.ObjectFactory(created_by_ref=IDENTITY_ID,
                                  granular_markings=marking)
    ind = factory.create(stix2.Indicator, **INDICATOR_KWARGS)
    assert "created_by_ref" in ind.granular_markings[0].selectors
