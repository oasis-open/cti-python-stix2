import stix2
from stix2.workbench import (add, all_versions, attack_patterns, campaigns,
                             courses_of_action, create, get, identities,
                             indicators, intrusion_sets, malware,
                             observed_data, query, reports, threat_actors,
                             tools, vulnerabilities)

from .constants import (ATTACK_PATTERN_ID, ATTACK_PATTERN_KWARGS, CAMPAIGN_ID,
                        CAMPAIGN_KWARGS, COURSE_OF_ACTION_ID,
                        COURSE_OF_ACTION_KWARGS, IDENTITY_ID, IDENTITY_KWARGS,
                        INDICATOR_ID, INDICATOR_KWARGS, INTRUSION_SET_ID,
                        INTRUSION_SET_KWARGS, MALWARE_ID, MALWARE_KWARGS,
                        OBSERVED_DATA_ID, OBSERVED_DATA_KWARGS, REPORT_ID,
                        REPORT_KWARGS, THREAT_ACTOR_ID, THREAT_ACTOR_KWARGS,
                        TOOL_ID, TOOL_KWARGS, VULNERABILITY_ID,
                        VULNERABILITY_KWARGS)


def test_workbench_environment():

    # Create a STIX object
    ind = create(stix2.Indicator, id=INDICATOR_ID, **INDICATOR_KWARGS)
    add(ind)

    resp = get(INDICATOR_ID)
    assert resp['labels'][0] == 'malicious-activity'

    resp = all_versions(INDICATOR_ID)
    assert len(resp) == 1

    # Search on something other than id
    q = [stix2.Filter('type', '=', 'vulnerability')]
    resp = query(q)
    assert len(resp) == 0


def test_workbench_get_all_attack_patterns():
    mal = stix2.AttackPattern(id=ATTACK_PATTERN_ID, **ATTACK_PATTERN_KWARGS)
    add(mal)

    resp = attack_patterns()
    assert len(resp) == 1
    assert resp[0].id == ATTACK_PATTERN_ID


def test_workbench_get_all_campaigns():
    cam = stix2.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    add(cam)

    resp = campaigns()
    assert len(resp) == 1
    assert resp[0].id == CAMPAIGN_ID


def test_workbench_get_all_courses_of_action():
    coa = stix2.CourseOfAction(id=COURSE_OF_ACTION_ID, **COURSE_OF_ACTION_KWARGS)
    add(coa)

    resp = courses_of_action()
    assert len(resp) == 1
    assert resp[0].id == COURSE_OF_ACTION_ID


def test_workbench_get_all_identities():
    idty = stix2.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    add(idty)

    resp = identities()
    assert len(resp) == 1
    assert resp[0].id == IDENTITY_ID


def test_workbench_get_all_indicators():
    resp = indicators()
    assert len(resp) == 1
    assert resp[0].id == INDICATOR_ID


def test_workbench_get_all_intrusion_sets():
    ins = stix2.IntrusionSet(id=INTRUSION_SET_ID, **INTRUSION_SET_KWARGS)
    add(ins)

    resp = intrusion_sets()
    assert len(resp) == 1
    assert resp[0].id == INTRUSION_SET_ID


def test_workbench_get_all_malware():
    mal = stix2.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    add(mal)

    resp = malware()
    assert len(resp) == 1
    assert resp[0].id == MALWARE_ID


def test_workbench_get_all_observed_data():
    od = stix2.ObservedData(id=OBSERVED_DATA_ID, **OBSERVED_DATA_KWARGS)
    add(od)

    resp = observed_data()
    assert len(resp) == 1
    assert resp[0].id == OBSERVED_DATA_ID


def test_workbench_get_all_reports():
    rep = stix2.Report(id=REPORT_ID, **REPORT_KWARGS)
    add(rep)

    resp = reports()
    assert len(resp) == 1
    assert resp[0].id == REPORT_ID


def test_workbench_get_all_threat_actors():
    thr = stix2.ThreatActor(id=THREAT_ACTOR_ID, **THREAT_ACTOR_KWARGS)
    add(thr)

    resp = threat_actors()
    assert len(resp) == 1
    assert resp[0].id == THREAT_ACTOR_ID


def test_workbench_get_all_tools():
    tool = stix2.Tool(id=TOOL_ID, **TOOL_KWARGS)
    add(tool)

    resp = tools()
    assert len(resp) == 1
    assert resp[0].id == TOOL_ID


def test_workbench_get_all_vulnerabilities():
    vuln = stix2.Vulnerability(id=VULNERABILITY_ID, **VULNERABILITY_KWARGS)
    add(vuln)

    resp = vulnerabilities()
    assert len(resp) == 1
    assert resp[0].id == VULNERABILITY_ID


def test_workbench_relationships():
    rel = stix2.Relationship(INDICATOR_ID, 'indicates', MALWARE_ID)
    add(rel)

    ind = get(INDICATOR_ID)
    resp = ind.relationships()
    assert len(resp) == 1
    assert resp[0].relationship_type == 'indicates'
    assert resp[0].source_ref == INDICATOR_ID
    assert resp[0].target_ref == MALWARE_ID


def test_workbench_created_by():
    intset = stix2.IntrusionSet(name="Breach 123", created_by_ref=IDENTITY_ID)
    add(intset)
    creator = intset.created_by()
    assert creator.id == IDENTITY_ID


def test_workbench_related():
    rel1 = stix2.Relationship(MALWARE_ID, 'targets', IDENTITY_ID)
    rel2 = stix2.Relationship(CAMPAIGN_ID, 'uses', MALWARE_ID)
    add([rel1, rel2])

    resp = get(MALWARE_ID).related()
    assert len(resp) == 3
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)
    assert any(x['id'] == IDENTITY_ID for x in resp)
