import os

import stix2
from stix2.workbench import (
    AttackPattern, Campaign, CourseOfAction, ExternalReference,
    FileSystemSource, Filter, Identity, Indicator, IntrusionSet, Malware,
    MarkingDefinition, ObservedData, Relationship, Report, StatementMarking,
    ThreatActor, Tool, Vulnerability, add_data_source, all_versions,
    attack_patterns, campaigns, courses_of_action, create, get, identities,
    indicators, intrusion_sets, malware, observed_data, query, reports, save,
    set_default_created, set_default_creator, set_default_external_refs,
    set_default_object_marking_refs, threat_actors, tools, vulnerabilities,
)

from .constants import (
    ATTACK_PATTERN_ID, ATTACK_PATTERN_KWARGS, CAMPAIGN_ID, CAMPAIGN_KWARGS,
    COURSE_OF_ACTION_ID, COURSE_OF_ACTION_KWARGS, IDENTITY_ID, IDENTITY_KWARGS,
    INDICATOR_ID, INDICATOR_KWARGS, INTRUSION_SET_ID, INTRUSION_SET_KWARGS,
    MALWARE_ID, MALWARE_KWARGS, OBSERVED_DATA_ID, OBSERVED_DATA_KWARGS,
    REPORT_ID, REPORT_KWARGS, THREAT_ACTOR_ID, THREAT_ACTOR_KWARGS, TOOL_ID,
    TOOL_KWARGS, VULNERABILITY_ID, VULNERABILITY_KWARGS,
)


def test_workbench_environment():

    # Create a STIX object
    ind = create(Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    save(ind)

    resp = get(INDICATOR_ID)
    assert resp['labels'][0] == 'malicious-activity'

    resp = all_versions(INDICATOR_ID)
    assert len(resp) == 1

    # Search on something other than id
    q = [Filter('type', '=', 'vulnerability')]
    resp = query(q)
    assert len(resp) == 0


def test_workbench_get_all_attack_patterns():
    mal = AttackPattern(id=ATTACK_PATTERN_ID, **ATTACK_PATTERN_KWARGS)
    save(mal)

    resp = attack_patterns()
    assert len(resp) == 1
    assert resp[0].id == ATTACK_PATTERN_ID


def test_workbench_get_all_campaigns():
    cam = Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    save(cam)

    resp = campaigns()
    assert len(resp) == 1
    assert resp[0].id == CAMPAIGN_ID


def test_workbench_get_all_courses_of_action():
    coa = CourseOfAction(id=COURSE_OF_ACTION_ID, **COURSE_OF_ACTION_KWARGS)
    save(coa)

    resp = courses_of_action()
    assert len(resp) == 1
    assert resp[0].id == COURSE_OF_ACTION_ID


def test_workbench_get_all_identities():
    idty = Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    save(idty)

    resp = identities()
    assert len(resp) == 1
    assert resp[0].id == IDENTITY_ID


def test_workbench_get_all_indicators():
    resp = indicators()
    assert len(resp) == 1
    assert resp[0].id == INDICATOR_ID


def test_workbench_get_all_intrusion_sets():
    ins = IntrusionSet(id=INTRUSION_SET_ID, **INTRUSION_SET_KWARGS)
    save(ins)

    resp = intrusion_sets()
    assert len(resp) == 1
    assert resp[0].id == INTRUSION_SET_ID


def test_workbench_get_all_malware():
    mal = Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    save(mal)

    resp = malware()
    assert len(resp) == 1
    assert resp[0].id == MALWARE_ID


def test_workbench_get_all_observed_data():
    od = ObservedData(id=OBSERVED_DATA_ID, **OBSERVED_DATA_KWARGS)
    save(od)

    resp = observed_data()
    assert len(resp) == 1
    assert resp[0].id == OBSERVED_DATA_ID


def test_workbench_get_all_reports():
    rep = Report(id=REPORT_ID, **REPORT_KWARGS)
    save(rep)

    resp = reports()
    assert len(resp) == 1
    assert resp[0].id == REPORT_ID


def test_workbench_get_all_threat_actors():
    thr = ThreatActor(id=THREAT_ACTOR_ID, **THREAT_ACTOR_KWARGS)
    save(thr)

    resp = threat_actors()
    assert len(resp) == 1
    assert resp[0].id == THREAT_ACTOR_ID


def test_workbench_get_all_tools():
    tool = Tool(id=TOOL_ID, **TOOL_KWARGS)
    save(tool)

    resp = tools()
    assert len(resp) == 1
    assert resp[0].id == TOOL_ID


def test_workbench_get_all_vulnerabilities():
    vuln = Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
    save(vuln)

    resp = vulnerabilities()
    assert len(resp) == 1
    assert resp[0].id == VULNERABILITY_ID


def test_workbench_add_to_bundle():
    vuln = Vulnerability(**VULNERABILITY_KWARGS)
    bundle = stix2.v20.Bundle(vuln)
    assert bundle.objects[0].name == 'Heartbleed'


def test_workbench_relationships():
    rel = Relationship(INDICATOR_ID, 'indicates', MALWARE_ID)
    save(rel)

    ind = get(INDICATOR_ID)
    resp = ind.relationships()
    assert len(resp) == 1
    assert resp[0].relationship_type == 'indicates'
    assert resp[0].source_ref == INDICATOR_ID
    assert resp[0].target_ref == MALWARE_ID


def test_workbench_created_by():
    intset = IntrusionSet(name="Breach 123", created_by_ref=IDENTITY_ID)
    save(intset)
    creator = intset.created_by()
    assert creator.id == IDENTITY_ID


def test_workbench_related():
    rel1 = Relationship(MALWARE_ID, 'targets', IDENTITY_ID)
    rel2 = Relationship(CAMPAIGN_ID, 'uses', MALWARE_ID)
    save([rel1, rel2])

    resp = get(MALWARE_ID).related()
    assert len(resp) == 3
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)
    assert any(x['id'] == IDENTITY_ID for x in resp)

    resp = get(MALWARE_ID).related(relationship_type='indicates')
    assert len(resp) == 1


def test_workbench_related_with_filters():
    malware = Malware(labels=["ransomware"], name="CryptorBit", created_by_ref=IDENTITY_ID)
    rel = Relationship(malware.id, 'variant-of', MALWARE_ID)
    save([malware, rel])

    filters = [Filter('created_by_ref', '=', IDENTITY_ID)]
    resp = get(MALWARE_ID).related(filters=filters)

    assert len(resp) == 1
    assert resp[0].name == malware.name
    assert resp[0].created_by_ref == IDENTITY_ID

    # filters arg can also be single filter
    resp = get(MALWARE_ID).related(filters=filters[0])
    assert len(resp) == 1


def test_add_data_source():
    fs_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "stix2_data")
    fs = FileSystemSource(fs_path)
    add_data_source(fs)

    resp = tools()
    assert len(resp) == 3
    resp_ids = [tool.id for tool in resp]
    assert TOOL_ID in resp_ids
    assert 'tool--03342581-f790-4f03-ba41-e82e67392e23' in resp_ids
    assert 'tool--242f3da3-4425-4d11-8f5c-b842886da966' in resp_ids


def test_additional_filter():
    resp = tools(Filter('created_by_ref', '=', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'))
    assert len(resp) == 2


def test_additional_filters_list():
    resp = tools([
        Filter('created_by_ref', '=', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'),
        Filter('name', '=', 'Windows Credential Editor'),
    ])
    assert len(resp) == 1


def test_default_creator():
    set_default_creator(IDENTITY_ID)
    campaign = Campaign(**CAMPAIGN_KWARGS)

    assert 'created_by_ref' not in CAMPAIGN_KWARGS
    assert campaign.created_by_ref == IDENTITY_ID


def test_default_created_timestamp():
    timestamp = "2018-03-19T01:02:03.000Z"
    set_default_created(timestamp)
    campaign = Campaign(**CAMPAIGN_KWARGS)

    assert 'created' not in CAMPAIGN_KWARGS
    assert stix2.utils.format_datetime(campaign.created) == timestamp
    assert stix2.utils.format_datetime(campaign.modified) == timestamp


def test_default_external_refs():
    ext_ref = ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
    )
    set_default_external_refs(ext_ref)
    campaign = Campaign(**CAMPAIGN_KWARGS)

    assert campaign.external_references[0].source_name == "ACME Threat Intel"
    assert campaign.external_references[0].description == "Threat report"


def test_default_object_marking_refs():
    stmt_marking = StatementMarking("Copyright 2016, Example Corp")
    mark_def = MarkingDefinition(
        definition_type="statement",
        definition=stmt_marking,
    )
    set_default_object_marking_refs(mark_def)
    campaign = Campaign(**CAMPAIGN_KWARGS)

    assert campaign.object_marking_refs[0] == mark_def.id


def test_workbench_custom_property_object_in_observable_extension():
    ntfs = stix2.v20.NTFSExt(
        allow_custom=True,
        sid=1,
        x_foo='bar',
    )
    artifact = stix2.v20.File(
        name='test',
        extensions={'ntfs-ext': ntfs},
    )
    observed_data = ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_workbench_custom_property_dict_in_observable_extension():
    artifact = stix2.v20.File(
        allow_custom=True,
        name='test',
        extensions={
            'ntfs-ext': {
                'allow_custom': True,
                'sid': 1,
                'x_foo': 'bar',
            },
        },
    )
    observed_data = ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)
