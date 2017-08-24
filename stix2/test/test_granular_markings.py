
import pytest

from stix2 import Malware, markings

from .constants import FAKE_TIME, MALWARE_ID, MARKING_IDS
from .constants import MALWARE_KWARGS as MALWARE_KWARGS_CONST

"""Tests for the Data Markings API."""

MALWARE_KWARGS = MALWARE_KWARGS_CONST.copy()
MALWARE_KWARGS.update({
    'id': MALWARE_ID,
    'created': FAKE_TIME,
    'modified': FAKE_TIME,
})


def test_add_marking_mark_one_selector_multiple_refs():
    before = Malware(
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[1]
            },
        ],
        **MALWARE_KWARGS
    )
    before = markings.add_markings(before, ["description"], [MARKING_IDS[0], MARKING_IDS[1]])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_add_marking_mark_multiple_selector_one_refs():
    before = Malware(
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description", "name"],
                "marking_ref": MARKING_IDS[0]
            },
        ],
        **MALWARE_KWARGS
    )
    before = markings.add_markings(before, ["description", "name"], [MARKING_IDS[0]])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_add_marking_mark_multiple_selector_multiple_refs():
    before = Malware(
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description", "name"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description", "name"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.add_markings(before, ["description", "name"], [MARKING_IDS[0], MARKING_IDS[1]])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_add_marking_mark_another_property_same_marking():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
        ],
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description", "name"],
                "marking_ref": MARKING_IDS[0]
            },
        ],
        **MALWARE_KWARGS
    )
    before = markings.add_markings(before, ["name"], [MARKING_IDS[0]])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_add_marking_mark_same_property_same_marking():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
        ],
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
        ],
        **MALWARE_KWARGS
    )
    before = markings.add_markings(before, ["description"], [MARKING_IDS[0]])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


@pytest.mark.parametrize("data,marking", [
    ({"description": "test description"},
     [["title"], ["marking-definition--1", "marking-definition--2"],
      "", ["marking-definition--1", "marking-definition--2"],
      [], ["marking-definition--1", "marking-definition--2"],
      [""], ["marking-definition--1", "marking-definition--2"],
      ["description"], [""],
      ["description"], [],
      ["description"], ["marking-definition--1", 456]
      ])
])
def test_add_marking_bad_selector(data, marking):
    with pytest.raises(AssertionError):
        markings.add_markings(data, marking[0], marking[1])


GET_MARKINGS_TEST_DATA = {
    "a": 333,
    "b": "value",
    "c": [
        17,
        "list value",
        {
            "g": "nested",
            "h": 45
        }
    ],
    "x": {
        "y": [
            "hello",
            88
        ],
        "z": {
            "foo1": "bar",
            "foo2": 65
        }
    },
    "granular_markings": [
        {
            "marking_ref": "1",
            "selectors": ["a"]
        },
        {
            "marking_ref": "2",
            "selectors": ["c"]
        },
        {
            "marking_ref": "3",
            "selectors": ["c.[1]"]
        },
        {
            "marking_ref": "4",
            "selectors": ["c.[2]"]
        },
        {
            "marking_ref": "5",
            "selectors": ["c.[2].g"]
        },
        {
            "marking_ref": "6",
            "selectors": ["x"]
        },
        {
            "marking_ref": "7",
            "selectors": ["x.y"]
        },
        {
            "marking_ref": "8",
            "selectors": ["x.y.[1]"]
        },
        {
            "marking_ref": "9",
            "selectors": ["x.z"]
        },
        {
            "marking_ref": "10",
            "selectors": ["x.z.foo2"]
        },
    ]
}


@pytest.mark.parametrize("data", [GET_MARKINGS_TEST_DATA])
def test_get_markings_smoke(data):
    """Test get_markings does not fail."""
    assert len(markings.get_markings(data, "a")) >= 1
    assert markings.get_markings(data, "a") == ["1"]


@pytest.mark.parametrize("data", [GET_MARKINGS_TEST_DATA])
def test_get_markings_not_marked(data):
    """Test selector that is not marked returns empty list."""
    results = markings.get_markings(data, "b")
    assert len(results) == 0


@pytest.mark.parametrize("data", [GET_MARKINGS_TEST_DATA])
def test_get_markings_multiple_selectors(data):
    """Test multiple selectors return combination of markings."""
    total = markings.get_markings(data, ["x.y", "x.z"])
    xy_markings = markings.get_markings(data, ["x.y"])
    xz_markings = markings.get_markings(data, ["x.z"])

    assert set(xy_markings).issubset(total)
    assert set(xz_markings).issubset(total)
    assert set(xy_markings).union(xz_markings).issuperset(total)


@pytest.mark.parametrize("data,selector", [
    (GET_MARKINGS_TEST_DATA, "foo"),
    (GET_MARKINGS_TEST_DATA, ""),
    (GET_MARKINGS_TEST_DATA, []),
    (GET_MARKINGS_TEST_DATA, [""]),
    (GET_MARKINGS_TEST_DATA, "x.z.[-2]"),
    (GET_MARKINGS_TEST_DATA, "c.f"),
    (GET_MARKINGS_TEST_DATA, "c.[2].i"),
    (GET_MARKINGS_TEST_DATA, "c.[3]"),
    (GET_MARKINGS_TEST_DATA, "d"),
    (GET_MARKINGS_TEST_DATA, "x.[0]"),
    (GET_MARKINGS_TEST_DATA, "z.y.w"),
    (GET_MARKINGS_TEST_DATA, "x.z.[1]"),
    (GET_MARKINGS_TEST_DATA, "x.z.foo3")
])
def test_get_markings_bad_selector(data, selector):
    """Test bad selectors raise exception"""
    with pytest.raises(AssertionError):
        markings.get_markings(data, selector)


@pytest.mark.parametrize("data", [GET_MARKINGS_TEST_DATA])
def test_get_markings_positional_arguments_combinations(data):
    """Test multiple combinations for inherited and descendant markings."""
    assert set(markings.get_markings(data, "a", False, False)) == set(["1"])
    assert set(markings.get_markings(data, "a", True, False)) == set(["1"])
    assert set(markings.get_markings(data, "a", True, True)) == set(["1"])
    assert set(markings.get_markings(data, "a", False, True)) == set(["1"])

    assert set(markings.get_markings(data, "b", False, False)) == set([])
    assert set(markings.get_markings(data, "b", True, False)) == set([])
    assert set(markings.get_markings(data, "b", True, True)) == set([])
    assert set(markings.get_markings(data, "b", False, True)) == set([])

    assert set(markings.get_markings(data, "c", False, False)) == set(["2"])
    assert set(markings.get_markings(data, "c", True, False)) == set(["2"])
    assert set(markings.get_markings(data, "c", True, True)) == set(["2", "3", "4", "5"])
    assert set(markings.get_markings(data, "c", False, True)) == set(["2", "3", "4", "5"])

    assert set(markings.get_markings(data, "c.[0]", False, False)) == set([])
    assert set(markings.get_markings(data, "c.[0]", True, False)) == set(["2"])
    assert set(markings.get_markings(data, "c.[0]", True, True)) == set(["2"])
    assert set(markings.get_markings(data, "c.[0]", False, True)) == set([])

    assert set(markings.get_markings(data, "c.[1]", False, False)) == set(["3"])
    assert set(markings.get_markings(data, "c.[1]", True, False)) == set(["2", "3"])
    assert set(markings.get_markings(data, "c.[1]", True, True)) == set(["2", "3"])
    assert set(markings.get_markings(data, "c.[1]", False, True)) == set(["3"])

    assert set(markings.get_markings(data, "c.[2]", False, False)) == set(["4"])
    assert set(markings.get_markings(data, "c.[2]", True, False)) == set(["2", "4"])
    assert set(markings.get_markings(data, "c.[2]", True, True)) == set(["2", "4", "5"])
    assert set(markings.get_markings(data, "c.[2]", False, True)) == set(["4", "5"])

    assert set(markings.get_markings(data, "c.[2].g", False, False)) == set(["5"])
    assert set(markings.get_markings(data, "c.[2].g", True, False)) == set(["2", "4", "5"])
    assert set(markings.get_markings(data, "c.[2].g", True, True)) == set(["2", "4", "5"])
    assert set(markings.get_markings(data, "c.[2].g", False, True)) == set(["5"])

    assert set(markings.get_markings(data, "x", False, False)) == set(["6"])
    assert set(markings.get_markings(data, "x", True, False)) == set(["6"])
    assert set(markings.get_markings(data, "x", True, True)) == set(["6", "7", "8", "9", "10"])
    assert set(markings.get_markings(data, "x", False, True)) == set(["6", "7", "8", "9", "10"])

    assert set(markings.get_markings(data, "x.y", False, False)) == set(["7"])
    assert set(markings.get_markings(data, "x.y", True, False)) == set(["6", "7"])
    assert set(markings.get_markings(data, "x.y", True, True)) == set(["6", "7", "8"])
    assert set(markings.get_markings(data, "x.y", False, True)) == set(["7", "8"])

    assert set(markings.get_markings(data, "x.y.[0]", False, False)) == set([])
    assert set(markings.get_markings(data, "x.y.[0]", True, False)) == set(["6", "7"])
    assert set(markings.get_markings(data, "x.y.[0]", True, True)) == set(["6", "7"])
    assert set(markings.get_markings(data, "x.y.[0]", False, True)) == set([])

    assert set(markings.get_markings(data, "x.y.[1]", False, False)) == set(["8"])
    assert set(markings.get_markings(data, "x.y.[1]", True, False)) == set(["6", "7", "8"])
    assert set(markings.get_markings(data, "x.y.[1]", True, True)) == set(["6", "7", "8"])
    assert set(markings.get_markings(data, "x.y.[1]", False, True)) == set(["8"])

    assert set(markings.get_markings(data, "x.z", False, False)) == set(["9"])
    assert set(markings.get_markings(data, "x.z", True, False)) == set(["6", "9"])
    assert set(markings.get_markings(data, "x.z", True, True)) == set(["6", "9", "10"])
    assert set(markings.get_markings(data, "x.z", False, True)) == set(["9", "10"])

    assert set(markings.get_markings(data, "x.z.foo1", False, False)) == set([])
    assert set(markings.get_markings(data, "x.z.foo1", True, False)) == set(["6", "9"])
    assert set(markings.get_markings(data, "x.z.foo1", True, True)) == set(["6", "9"])
    assert set(markings.get_markings(data, "x.z.foo1", False, True)) == set([])

    assert set(markings.get_markings(data, "x.z.foo2", False, False)) == set(["10"])
    assert set(markings.get_markings(data, "x.z.foo2", True, False)) == set(["6", "9", "10"])
    assert set(markings.get_markings(data, "x.z.foo2", True, True)) == set(["6", "9", "10"])
    assert set(markings.get_markings(data, "x.z.foo2", False, True)) == set(["10"])


def test_remove_marking_remove_one_selector_with_multiple_refs():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["description"], [MARKING_IDS[0], MARKING_IDS[1]])
    assert "granular_markings" not in before


def test_remove_marking_remove_multiple_selector_one_ref():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["description", "modified"], [MARKING_IDS[0]])
    assert "granular_markings" not in before


def test_remove_marking_mark_one_selector_from_multiple_ones():
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["modified"], [MARKING_IDS[0]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_remove_marking_mark_one_selector_markings_from_multiple_ones():
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["modified"], [MARKING_IDS[0]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_remove_marking_mark_mutilple_selector_multiple_refs():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["description", "modified"], [MARKING_IDS[0], MARKING_IDS[1]])
    assert "granular_markings" not in before


def test_remove_marking_mark_another_property_same_marking():
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["modified"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["modified"], [MARKING_IDS[0]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_remove_marking_mark_same_property_same_marking():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.remove_markings(before, ["description"], [MARKING_IDS[0]])
    assert "granular_markings" not in before


def test_remove_marking_bad_selector():
    before = {
        "description": "test description",
    }
    with pytest.raises(AssertionError):
        markings.remove_markings(before, ["title"], ["marking-definition--1", "marking-definition--2"])


IS_MARKED_TEST_DATA = {
    "title": "test title",
    "description": "test description",
    "revision": 2,
    "type": "test",
    "granular_markings": [
        {
            "selectors": ["description"],
            "marking_ref": "marking-definition--1"
        },
        {
            "selectors": ["revision", "description"],
            "marking_ref": "marking-definition--2"
        },
        {
            "selectors": ["revision", "description"],
            "marking_ref": "marking-definition--3"
        },
    ]
}


@pytest.mark.parametrize("data", [IS_MARKED_TEST_DATA])
def test_is_marked_smoke(data):
    """Smoke test is_marked call does not fail."""
    assert markings.is_marked(data, ["description"])
    assert markings.is_marked(data, ["title"]) is False


@pytest.mark.parametrize("data,selector", [
    (IS_MARKED_TEST_DATA, "foo"),
    (IS_MARKED_TEST_DATA, ""),
    (IS_MARKED_TEST_DATA, []),
    (IS_MARKED_TEST_DATA, [""]),
    (IS_MARKED_TEST_DATA, "x.z.[-2]"),
    (IS_MARKED_TEST_DATA, "c.f"),
    (IS_MARKED_TEST_DATA, "c.[2].i"),
    (IS_MARKED_TEST_DATA, "c.[3]"),
    (IS_MARKED_TEST_DATA, "d"),
    (IS_MARKED_TEST_DATA, "x.[0]"),
    (IS_MARKED_TEST_DATA, "z.y.w"),
    (IS_MARKED_TEST_DATA, "x.z.[1]"),
    (IS_MARKED_TEST_DATA, "x.z.foo3")
])
def test_is_marked_invalid_selector(data, selector):
    """Test invalid selector raises an error."""
    with pytest.raises(AssertionError):
        markings.is_marked(data, selector)


@pytest.mark.parametrize("data", [IS_MARKED_TEST_DATA])
def test_is_marked_mix_selector(data):
    """Test valid selector, one marked and one not marked returns True."""
    assert markings.is_marked(data, ["description", "revision"])
    assert markings.is_marked(data, ["description"])


@pytest.mark.parametrize("data", [IS_MARKED_TEST_DATA])
def test_is_marked_valid_selector_no_refs(data):
    """Test that a valid selector return True when it has marking refs and False when not."""
    assert markings.is_marked(data, ["description"])
    assert markings.is_marked(data, ["description"], ["marking-definition--2", "marking-definition--3"])
    assert markings.is_marked(data, ["description"], ["marking-definition--2"])
    assert markings.is_marked(data, ["description"], ["marking-definition--2", "marking-definition--8"]) is False


@pytest.mark.parametrize("data", [IS_MARKED_TEST_DATA])
def test_is_marked_valid_selector_and_refs(data):
    """Test that a valid selector returns True when marking_refs match."""
    assert markings.is_marked(data, ["description"], ["marking-definition--1"])
    assert markings.is_marked(data, ["title"], ["marking-definition--1"]) is False


@pytest.mark.parametrize("data", [IS_MARKED_TEST_DATA])
def test_is_marked_valid_selector_multiple_refs(data):
    """Test that a valid selector returns True if aall marking_refs match.
        Otherwise False."""
    assert markings.is_marked(data, ["revision"], ["marking-definition--2", "marking-definition--3"])
    assert markings.is_marked(data, ["revision"], ["marking-definition--2", "marking-definition--1"]) is False
    assert markings.is_marked(data, ["revision"], "marking-definition--2")
    assert markings.is_marked(data, ["revision"], ["marking-definition--1234"]) is False


@pytest.mark.parametrize("data", [IS_MARKED_TEST_DATA])
def test_is_marked_no_marking_refs(data):
    """Test that a valid content selector with no marking_refs returns True
        if there is a granular_marking that asserts that field, False
        otherwise."""
    assert markings.is_marked(data, ["type"]) is False
    assert markings.is_marked(data, ["revision"])


def test_is_marked_positional_arguments_combinations():
    """Test multiple combinations for inherited and descendant markings."""
    test_tlo = \
        {
            "a": 333,
            "b": "value",
            "c": [
                17,
                "list value",
                {
                    "g": "nested",
                    "h": 45
                }
            ],
            "x": {
                "y": [
                    "hello",
                    88
                ],
                "z": {
                    "foo1": "bar",
                    "foo2": 65
                }
            },
            "granular_markings": [
                {
                    "marking_ref": "1",
                    "selectors": ["a"]
                },
                {
                    "marking_ref": "2",
                    "selectors": ["c"]
                },
                {
                    "marking_ref": "3",
                    "selectors": ["c.[1]"]
                },
                {
                    "marking_ref": "4",
                    "selectors": ["c.[2]"]
                },
                {
                    "marking_ref": "5",
                    "selectors": ["c.[2].g"]
                },
                {
                    "marking_ref": "6",
                    "selectors": ["x"]
                },
                {
                    "marking_ref": "7",
                    "selectors": ["x.y"]
                },
                {
                    "marking_ref": "8",
                    "selectors": ["x.y.[1]"]
                },
                {
                    "marking_ref": "9",
                    "selectors": ["x.z"]
                },
                {
                    "marking_ref": "10",
                    "selectors": ["x.z.foo2"]
                },
            ]
        }

    assert markings.is_marked(test_tlo, "a", ["1"], False, False)
    assert markings.is_marked(test_tlo, "a", ["1"], True, False)
    assert markings.is_marked(test_tlo, "a", ["1"], True, True)
    assert markings.is_marked(test_tlo, "a", ["1"], False, True)

    assert markings.is_marked(test_tlo, "b", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "b", inherited=True, descendants=False) is False
    assert markings.is_marked(test_tlo, "b", inherited=True, descendants=True) is False
    assert markings.is_marked(test_tlo, "b", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "c", ["2"], False, False)
    assert markings.is_marked(test_tlo, "c", ["2"], True, False)
    assert markings.is_marked(test_tlo, "c", ["2", "3", "4", "5"], True, True)
    assert markings.is_marked(test_tlo, "c", ["2", "3", "4", "5"], False, True)

    assert markings.is_marked(test_tlo, "c.[0]", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "c.[0]", ["2"], True, False)
    assert markings.is_marked(test_tlo, "c.[0]", ["2"], True, True)
    assert markings.is_marked(test_tlo, "c.[0]", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "c.[1]", ["3"], False, False)
    assert markings.is_marked(test_tlo, "c.[1]", ["2", "3"], True, False)
    assert markings.is_marked(test_tlo, "c.[1]", ["2", "3"], True, True)
    assert markings.is_marked(test_tlo, "c.[1]", ["3"], False, True)

    assert markings.is_marked(test_tlo, "c.[2]", ["4"], False, False)
    assert markings.is_marked(test_tlo, "c.[2]", ["2", "4"], True, False)
    assert markings.is_marked(test_tlo, "c.[2]", ["2", "4", "5"], True, True)
    assert markings.is_marked(test_tlo, "c.[2]", ["4", "5"], False, True)

    assert markings.is_marked(test_tlo, "c.[2].g", ["5"], False, False)
    assert markings.is_marked(test_tlo, "c.[2].g", ["2", "4", "5"], True, False)
    assert markings.is_marked(test_tlo, "c.[2].g", ["2", "4", "5"], True, True)
    assert markings.is_marked(test_tlo, "c.[2].g", ["5"], False, True)

    assert markings.is_marked(test_tlo, "x", ["6"], False, False)
    assert markings.is_marked(test_tlo, "x", ["6"], True, False)
    assert markings.is_marked(test_tlo, "x", ["6", "7", "8", "9", "10"], True, True)
    assert markings.is_marked(test_tlo, "x", ["6", "7", "8", "9", "10"], False, True)

    assert markings.is_marked(test_tlo, "x.y", ["7"], False, False)
    assert markings.is_marked(test_tlo, "x.y", ["6", "7"], True, False)
    assert markings.is_marked(test_tlo, "x.y", ["6", "7", "8"], True, True)
    assert markings.is_marked(test_tlo, "x.y", ["7", "8"], False, True)

    assert markings.is_marked(test_tlo, "x.y.[0]", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "x.y.[0]", ["6", "7"], True, False)
    assert markings.is_marked(test_tlo, "x.y.[0]", ["6", "7"], True, True)
    assert markings.is_marked(test_tlo, "x.y.[0]", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "x.y.[1]", ["8"], False, False)
    assert markings.is_marked(test_tlo, "x.y.[1]", ["6", "7", "8"], True, False)
    assert markings.is_marked(test_tlo, "x.y.[1]", ["6", "7", "8"], True, True)
    assert markings.is_marked(test_tlo, "x.y.[1]", ["8"], False, True)

    assert markings.is_marked(test_tlo, "x.z", ["9"], False, False)
    assert markings.is_marked(test_tlo, "x.z", ["6", "9"], True, False)
    assert markings.is_marked(test_tlo, "x.z", ["6", "9", "10"], True, True)
    assert markings.is_marked(test_tlo, "x.z", ["9", "10"], False, True)

    assert markings.is_marked(test_tlo, "x.z.foo1", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "x.z.foo1", ["6", "9"], True, False)
    assert markings.is_marked(test_tlo, "x.z.foo1", ["6", "9"], True, True)
    assert markings.is_marked(test_tlo, "x.z.foo1", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "x.z.foo2", ["10"], False, False)
    assert markings.is_marked(test_tlo, "x.z.foo2", ["6", "9", "10"], True, False)
    assert markings.is_marked(test_tlo, "x.z.foo2", ["6", "9", "10"], True, True)
    assert markings.is_marked(test_tlo, "x.z.foo2", ["10"], False, True)


def test_set_marking_mark_one_selector_multiple_refs():
    before = Malware(
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.set_markings(before, ["description"], [MARKING_IDS[0], MARKING_IDS[1]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_set_marking_mark_multiple_selector_one_refs():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.set_markings(before, ["description", "modified"], [MARKING_IDS[0]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_set_marking_mark_multiple_selector_multiple_refs_from_none():
    before = Malware(
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[0]
            },
            {
                "selectors": ["description", "modified"],
                "marking_ref": MARKING_IDS[1]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.set_markings(before, ["description", "modified"], [MARKING_IDS[0], MARKING_IDS[1]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


def test_set_marking_mark_another_property_same_marking():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[1]
            },
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[2]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.set_markings(before, ["description"], [MARKING_IDS[1], MARKING_IDS[2]])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


@pytest.mark.parametrize("marking", [
    (["foo"], ["marking-definition--7", "marking-definition--8"]),
    ("", ["marking-definition--7", "marking-definition--8"]),
    ([], ["marking-definition--7", "marking-definition--8"]),
    ([""], ["marking-definition--7", "marking-definition--8"])
])
def test_set_marking_bad_selector(marking):
    before = {
        "description": "test description",
        "title": "foo",
        "granular_markings": [
            {
                "selectors": ["description"],
                "marking_ref": "marking-definition--1"
            }
        ]
    }
    after = {
        "description": "test description",
        "title": "foo",
        "granular_markings": [
            {
                "selectors": ["description"],
                "marking_ref": "marking-definition--1"
            },
        ]
    }

    with pytest.raises(AssertionError):
        markings.set_markings(before, marking[0], marking[1])

    assert before == after


def test_set_marking_mark_same_property_same_marking():
    before = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    after = Malware(
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": MARKING_IDS[0]
            }
        ],
        **MALWARE_KWARGS
    )
    before = markings.set_markings(before, ["description"], [MARKING_IDS[0]])
    for m in before["granular_markings"]:
        assert m in after["granular_markings"]


CLEAR_MARKINGS_TEST_DATA = Malware(
    granular_markings=[
        {
            "selectors": ["description"],
            "marking_ref": MARKING_IDS[0]
        },
        {
            "selectors": ["modified", "description"],
            "marking_ref": MARKING_IDS[1]
        },
        {
            "selectors": ["modified", "description", "type"],
            "marking_ref": MARKING_IDS[2]
        },
    ],
    **MALWARE_KWARGS
)


@pytest.mark.parametrize("data", [CLEAR_MARKINGS_TEST_DATA])
def test_clear_marking_smoke(data):
    """Test clear_marking call does not fail."""
    data = markings.clear_markings(data, "modified")
    assert markings.is_marked(data, "modified") is False


@pytest.mark.parametrize("data", [CLEAR_MARKINGS_TEST_DATA])
def test_clear_marking_multiple_selectors(data):
    """Test clearing markings for multiple selectors effectively removes associated markings."""
    data = markings.clear_markings(data, ["type", "description"])
    assert markings.is_marked(data, ["type", "description"]) is False


@pytest.mark.parametrize("data", [CLEAR_MARKINGS_TEST_DATA])
def test_clear_marking_one_selector(data):
    """Test markings associated with one selector were removed."""
    data = markings.clear_markings(data, "description")
    assert markings.is_marked(data, "description") is False


@pytest.mark.parametrize("data", [CLEAR_MARKINGS_TEST_DATA])
def test_clear_marking_all_selectors(data):
    data = markings.clear_markings(data, ["description", "type", "modified"])
    assert markings.is_marked(data, "description") is False
    assert "granular_markings" not in data


@pytest.mark.parametrize("data,selector", [
    (CLEAR_MARKINGS_TEST_DATA, "foo"),
    (CLEAR_MARKINGS_TEST_DATA, ""),
    (CLEAR_MARKINGS_TEST_DATA, []),
    (CLEAR_MARKINGS_TEST_DATA, [""]),
])
def test_clear_marking_bad_selector(data, selector):
    """Test bad selector raises exception."""
    with pytest.raises(AssertionError):
        markings.clear_markings(data, selector)