import pytest

from stix2.equivalence.pattern import (
    equivalent_patterns, find_equivalent_patterns,
)

# #                                          # #
# # Observation expression equivalence tests # #
# #                                          # #


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] OR [a:b=1]",
            "[a:b=1]",
        ),
        (
            "[a:b=1] OR [a:b=1] OR [a:b=1]",
            "[a:b=1]",
        ),
    ],
)
def test_obs_dupe_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] AND [a:b=1]",
            "[a:b=1]",
        ),
        (
            "[a:b=1] FOLLOWEDBY [a:b=1]",
            "[a:b=1]",
        ),
    ],
)
def test_obs_dupe_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        ("[a:b=1]", "([a:b=1])"),
        ("(((([a:b=1]))))", "([a:b=1])"),
        (
            "[a:b=1] AND ([a:b=2] AND [a:b=3])",
            "[a:b=1] AND [a:b=2] AND [a:b=3]",
        ),
        (
            "([a:b=1] AND [a:b=2]) AND [a:b=3]",
            "[a:b=1] AND ([a:b=2] AND [a:b=3])",
        ),
        (
            "[a:b=1] OR ([a:b=2] OR [a:b=3])",
            "[a:b=1] OR [a:b=2] OR [a:b=3]",
        ),
        (
            "([a:b=1] OR [a:b=2]) OR [a:b=3]",
            "[a:b=1] OR ([a:b=2] OR [a:b=3])",
        ),
        (
            "[a:b=1] FOLLOWEDBY ([a:b=2] FOLLOWEDBY [a:b=3])",
            "[a:b=1] FOLLOWEDBY [a:b=2] FOLLOWEDBY [a:b=3]",
        ),
        (
            "([a:b=1] FOLLOWEDBY [a:b=2]) FOLLOWEDBY [a:b=3]",
            "[a:b=1] FOLLOWEDBY ([a:b=2] FOLLOWEDBY [a:b=3])",
        ),
        (
            "[a:b=1] AND ([a:b=2] AND ([a:b=3] AND [a:b=4])) AND ([a:b=5])",
            "([a:b=1] AND ([a:b=2] AND [a:b=3]) AND ([a:b=4] AND [a:b=5]))",
        ),
    ],
)
def test_obs_flatten_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "([a:b=1] AND [a:b=2]) OR [a:b=3]",
            "[a:b=1] AND ([a:b=2] OR [a:b=3])",
        ),
        (
            "([a:b=1] OR [a:b=2]) FOLLOWEDBY [a:b=3]",
            "[a:b=1] OR ([a:b=2] FOLLOWEDBY [a:b=3])",
        ),
        ("[a:b=1]", "([a:b=1]) REPEATS 2 TIMES"),
        ("(((([a:b=1]))))", "([a:b=1] REPEATS 2 TIMES)"),
        (
            "[a:b=1] AND ([a:b=2] AND [a:b=3]) WITHIN 2 SECONDS",
            "[a:b=1] WITHIN 2 SECONDS AND [a:b=2] AND [a:b=3]",
        ),
        (
            "[a:b=1] OR ([a:b=2] OR [a:b=3]) WITHIN 2 SECONDS",
            "[a:b=1] WITHIN 2 SECONDS OR [a:b=2] OR [a:b=3]",
        ),
        (
            "[a:b=1] FOLLOWEDBY ([a:b=2] FOLLOWEDBY [a:b=3]) WITHIN 2 SECONDS",
            "[a:b=1] WITHIN 2 SECONDS FOLLOWEDBY [a:b=2] FOLLOWEDBY [a:b=3]",
        ),
    ],
)
def test_obs_flatten_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] AND [a:b=2]",
            "[a:b=2] AND [a:b=1]",
        ),
        (
            "[a:b=1] OR [a:b=2]",
            "[a:b=2] OR [a:b=1]",
        ),
        (
            "[a:b=1] OR ([a:b=2] AND [a:b=3])",
            "([a:b=3] AND [a:b=2]) OR [a:b=1]",
        ),
        (
            "[a:b=1] WITHIN 2 SECONDS AND [a:b=2] REPEATS 2 TIMES",
            "[a:b=2] REPEATS 2 TIMES AND [a:b=1] WITHIN 2 SECONDS",
        ),
    ],
)
def test_obs_order_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] FOLLOWEDBY [a:b=2]",
            "[a:b=2] FOLLOWEDBY [a:b=1]",
        ),
        (
            "[a:b=1] WITHIN 2 SECONDS AND [a:b=2] REPEATS 2 TIMES",
            "[a:b=1] REPEATS 2 TIMES AND [a:b=2] WITHIN 2 SECONDS",
        ),
    ],
)
def test_obs_order_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] OR ([a:b=1] AND [a:b=2])",
            "[a:b=1]",
        ),
        (
            "[a:b=1] OR ([a:b=1] FOLLOWEDBY [a:b=2])",
            "[a:b=1]",
        ),
        (
            "([a:b=3] AND [a:b=1]) OR ([a:b=1] AND [a:b=2] AND [a:b=3])",
            "[a:b=3] AND [a:b=1]",
        ),
        (
            "([a:b=1] FOLLOWEDBY [a:b=3]) OR ([a:b=4] FOLLOWEDBY [a:b=1] FOLLOWEDBY [a:b=2] FOLLOWEDBY [a:b=3])",
            "[a:b=1] FOLLOWEDBY [a:b=3]",
        ),
        (
            "([a:b=1] FOLLOWEDBY [a:b=2]) OR (([a:b=1] FOLLOWEDBY [a:b=2]) AND [a:b=3])",
            "[a:b=1] FOLLOWEDBY [a:b=2]",
        ),
        (
            "([a:b=1] AND [a:b=2]) OR (([a:b=1] AND [a:b=2]) FOLLOWEDBY [a:b=3])",
            "[a:b=1] AND [a:b=2]",
        ),
    ],
)
def test_obs_absorb_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "([a:b=1] AND [a:b=2]) OR ([a:b=2] AND [a:b=3] AND [a:b=4])",
            "[a:b=1] AND [a:b=2]",
        ),
        (
            "([a:b=2] FOLLOWEDBY [a:b=1]) OR ([a:b=1] FOLLOWEDBY [a:b=2] FOLLOWEDBY [a:b=3])",
            "[a:b=2] FOLLOWEDBY [a:b=1]",
        ),
    ],
)
def test_obs_absorb_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] AND ([a:b=2] OR [a:b=3])",
            "([a:b=1] AND [a:b=2]) OR ([a:b=1] AND [a:b=3])",
        ),
        (
            "[a:b=1] FOLLOWEDBY ([a:b=2] OR [a:b=3])",
            "([a:b=1] FOLLOWEDBY [a:b=2]) OR ([a:b=1] FOLLOWEDBY [a:b=3])",
        ),
        (
            "[a:b=1] AND ([a:b=2] AND ([a:b=3] OR [a:b=4]))",
            "([a:b=1] AND [a:b=2] AND [a:b=3]) OR ([a:b=1] AND [a:b=2] AND [a:b=4])",
        ),
        (
            "[a:b=1] FOLLOWEDBY ([a:b=2] FOLLOWEDBY ([a:b=3] OR [a:b=4]))",
            "([a:b=1] FOLLOWEDBY [a:b=2] FOLLOWEDBY [a:b=3]) OR ([a:b=1] FOLLOWEDBY [a:b=2] FOLLOWEDBY [a:b=4])",
        ),
        (
            "([a:b=1] OR [a:b=2]) AND ([a:b=3] OR [a:b=4])",
            "([a:b=1] AND [a:b=3]) OR ([a:b=1] AND [a:b=4]) OR ([a:b=2] AND [a:b=3]) OR ([a:b=2] AND [a:b=4])",
        ),
        (
            "([a:b=1] OR [a:b=2]) FOLLOWEDBY ([a:b=3] OR [a:b=4])",
            "([a:b=1] FOLLOWEDBY [a:b=3]) OR ([a:b=1] FOLLOWEDBY [a:b=4]) OR ([a:b=2] FOLLOWEDBY [a:b=3]) OR ([a:b=2] FOLLOWEDBY [a:b=4])",
        ),
        (
            "([a:b=1] OR [a:b=2]) FOLLOWEDBY ([a:b=5] AND [a:b=6])",
            "([a:b=1] FOLLOWEDBY ([a:b=5] AND [a:b=6])) OR ([a:b=2] FOLLOWEDBY ([a:b=5] AND [a:b=6]))",
        ),
    ],
)
def test_obs_dnf_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] AND [a:b=2]",
            "[a:b=1] OR [a:b=2]",
        ),
        (
            "[a:b=1] AND ([a:b=2] OR [a:b=3])",
            "([a:b=1] AND [a:b=2]) OR [a:b=3]",
        ),
        (
            "[a:b=1] WITHIN 2 SECONDS",
            "[a:b=1] REPEATS 2 TIMES",
        ),
        (
            "[a:b=1] FOLLOWEDBY ([a:b=2] OR [a:b=3])",
            "([a:b=2] FOLLOWEDBY [a:b=1]) OR ([a:b=1] FOLLOWEDBY [a:b=3])",
        ),
    ],
)
def test_obs_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


# #                                         # #
# # Comparison expression equivalence tests # #
# #                                         # #


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1 AND a:b=1]",
            "[a:b=1]",
        ),
        (
            "[a:b=1 AND a:b=1 AND a:b=1]",
            "[a:b=1]",
        ),
        (
            "[a:b=1 OR a:b=1]",
            "[a:b=1]",
        ),
        (
            "[a:b=1 OR a:b=1 OR a:b=1]",
            "[a:b=1]",
        ),
    ],
)
def test_comp_dupe_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[(a:b=1)]",
            "[a:b=1]",
        ),
        (
            "[(((((a:b=1)))))]",
            "[(a:b=1)]",
        ),
        (
            "[a:b=1 AND (a:b=2 AND a:b=3)]",
            "[(a:b=1 AND a:b=2) AND a:b=3]",
        ),
        (
            "[a:b=1 OR (a:b=2 OR a:b=3)]",
            "[(a:b=1 OR a:b=2) OR a:b=3]",
        ),
        (
            "[(((a:b=1 AND ((a:b=2) AND a:b=3) AND (a:b=4))))]",
            "[a:b=1 AND a:b=2 AND a:b=3 AND a:b=4]",
        ),
        (
            "[(((a:b=1 OR ((a:b=2) OR a:b=3) OR (a:b=4))))]",
            "[a:b=1 OR a:b=2 OR a:b=3 OR a:b=4]",
        ),
    ],
)
def test_comp_flatten_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1 AND a:b=2]",
            "[a:b=2 AND a:b=1]",
        ),
        (
            "[a:b=1 OR a:b=2]",
            "[a:b=2 OR a:b=1]",
        ),
        (
            "[(a:b=1 OR a:b=2) AND a:b=3]",
            "[a:b=3 AND (a:b=2 OR a:b=1)]",
        ),
    ],
)
def test_comp_order_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1 OR (a:b=1 AND a:b=2)]",
            "[a:b=1]",
        ),
        (
            "[a:b=1 AND (a:b=1 OR a:b=2)]",
            "[a:b=1]",
        ),
        (
            "[(a:b=1 AND a:b=2) OR (a:b=3 AND a:b=2 AND a:b=1)]",
            "[a:b=1 AND a:b=2]",
        ),
        (
            "[(a:b=1 OR a:b=2) AND (a:b=3 OR a:b=2 OR a:b=1)]",
            "[a:b=1 OR a:b=2]",
        ),
    ],
)
def test_comp_absorb_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1 OR (a:b=2 AND a:b=3)]",
            "[(a:b=1 OR a:b=2) AND (a:b=1 OR a:b=3)]",
        ),
        (
            "[a:b=1 AND (a:b=2 OR a:b=3)]",
            "[(a:b=1 AND a:b=2) OR (a:b=1 AND a:b=3)]",
        ),
        (
            "[(a:b=1 AND a:b=2) OR (a:b=3 AND a:b=4)]",
            "[(a:b=1 OR a:b=3) AND (a:b=1 OR a:b=4) AND (a:b=2 OR a:b=3) AND (a:b=2 OR a:b=4)]",
        ),
        (
            "[(a:b=1 OR a:b=2) AND (a:b=3 OR a:b=4)]",
            "[(a:b=1 AND a:b=3) OR (a:b=1 AND a:b=4) OR (a:b=2 AND a:b=3) OR (a:b=2 AND a:b=4)]",
        ),
        (
            "[a:b=1 AND (a:b=2 AND (a:b=3 OR a:b=4))]",
            "[(a:b=1 AND a:b=2 AND a:b=3) OR (a:b=1 AND a:b=2 AND a:b=4)]",
        ),
        # Some tests with different SCO types
        (
            "[(a:b=1 OR b:c=1) AND (b:d=1 OR c:d=1)]",
            "[b:c=1 AND b:d=1]",
        ),
        (
            "[(a:b=1 OR b:c=1) AND (b:d=1 OR c:d=1)]",
            "[(z:y=1 OR b:c=1) AND (b:d=1 OR x:w=1 OR v:u=1)]",
        ),
    ],
)
def test_comp_dnf_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1]",
            "[a:b=2]",
        ),
        (
            "[a:b=1 AND a:b=2]",
            "[a:b=1 OR a:b=2]",
        ),
        (
            "[(a:b=1 AND a:b=2) OR a:b=3]",
            "[a:b=1 AND (a:b=2 OR a:b=3)]",
        ),
    ],
)
def test_comp_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[ipv4-addr:value='1.2.3.4/32']",
            "[ipv4-addr:value='1.2.3.4']",
        ),
        (
            "[ipv4-addr:value='1.2.3.4/24']",
            "[ipv4-addr:value='1.2.3.0/24']",
        ),
        (
            "[ipv4-addr:value='1.2.255.4/23']",
            "[ipv4-addr:value='1.2.254.0/23']",
        ),
        (
            "[ipv4-addr:value='1.2.255.4/20']",
            "[ipv4-addr:value='1.2.240.0/20']",
        ),
        (
            "[ipv4-addr:value='1.2.255.4/0']",
            "[ipv4-addr:value='0.0.0.0/0']",
        ),
        (
            "[ipv4-addr:value='01.02.03.04']",
            "[ipv4-addr:value='1.2.3.4']",
        ),
        (
            "[ipv4-addr:value='1.2.3.4/-5']",
            "[ipv4-addr:value='1.2.3.4/-5']",
        ),
        (
            "[ipv4-addr:value='1.2.3.4/99']",
            "[ipv4-addr:value='1.2.3.4/99']",
        ),
        (
            "[ipv4-addr:value='foo']",
            "[ipv4-addr:value='foo']",
        ),
    ],
)
def test_comp_special_canonicalization_ipv4(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[ipv4-addr:value='1.2.3.4']",
            "[ipv4-addr:value='1.2.3.5']",
        ),
        (
            "[ipv4-addr:value='1.2.3.4/1']",
            "[ipv4-addr:value='1.2.3.4/2']",
        ),
        (
            "[ipv4-addr:value='foo']",
            "[ipv4-addr:value='bar']",
        ),
    ],
)
def test_comp_special_canonicalization_ipv4_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/128']",
            "[ipv6-addr:value='1:2:3:4:5:6:7:8']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/112']",
            "[ipv6-addr:value='1:2:3:4:5:6:7:0/112']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:ffff:8/111']",
            "[ipv6-addr:value='1:2:3:4:5:6:fffe:0/111']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:ffff:8/104']",
            "[ipv6-addr:value='1:2:3:4:5:6:ff00:0/104']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/0']",
            "[ipv6-addr:value='0:0:0:0:0:0:0:0/0']",
        ),
        (
            "[ipv6-addr:value='0001:0000:0000:0000:0000:0000:0000:0001']",
            "[ipv6-addr:value='1::1']",
        ),
        (
            "[ipv6-addr:value='0000:0000:0000:0000:0000:0000:0000:0000']",
            "[ipv6-addr:value='::']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/-5']",
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/-5']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/99']",
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/99']",
        ),
        (
            "[ipv6-addr:value='foo']",
            "[ipv6-addr:value='foo']",
        ),
    ],
)
def test_comp_special_canonicalization_ipv6(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8']",
            "[ipv6-addr:value='1:2:3:4:5:6:7:9']",
        ),
        (
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/1']",
            "[ipv6-addr:value='1:2:3:4:5:6:7:8/2']",
        ),
        (
            "[ipv6-addr:value='foo']",
            "[ipv6-addr:value='bar']",
        ),
    ],
)
def test_comp_special_canonicalization_ipv6_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[windows-registry-key:key = 'aaa']",
            "[windows-registry-key:key = 'AAA']",
        ),
        (
            "[windows-registry-key:values[0].name = 'aaa']",
            "[windows-registry-key:values[0].name = 'AAA']",
        ),
        (
            "[windows-registry-key:values[*].name = 'aaa']",
            "[windows-registry-key:values[*].name = 'AAA']",
        ),
    ],
)
def test_comp_special_canonicalization_win_reg_key(patt1, patt2):
    assert equivalent_patterns(patt1, patt2)


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[windows-registry-key:key='foo']",
            "[windows-registry-key:key='bar']",
        ),
        (
            "[windows-registry-key:values[0].name='foo']",
            "[windows-registry-key:values[0].name='bar']",
        ),
        (
            "[windows-registry-key:values[*].name='foo']",
            "[windows-registry-key:values[*].name='bar']",
        ),
        (
            "[windows-registry-key:values[*].data='foo']",
            "[windows-registry-key:values[*].data='FOO']",
        ),
    ],
)
def test_comp_special_canonicalization_win_reg_key_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2)


def test_comp_other_constant_types():
    constants = [
        "1.23",
        "1",
        "true",
        "false",
        "h'4fa2'",
        "b'ZmpoZWll'",
        "t'1982-12-31T02:14:17.232Z'",
    ]

    pattern_template = "[a:b={}]"
    for i, const1 in enumerate(constants):
        for j, const2 in enumerate(constants):
            patt1 = pattern_template.format(const1)
            patt2 = pattern_template.format(const2)

            if i == j:
                assert equivalent_patterns(patt1, patt2)
            else:
                assert not equivalent_patterns(patt1, patt2)

    # can't use an "=" pattern with lists...
    for const in constants:
        patt1 = "[a:b={}]".format(const)
        patt2 = "[a:b IN (1,2,3)]"
        assert not equivalent_patterns(patt1, patt2)


# #                                  # #
# # find_equivalent_patterns() tests # #
# #                                  # #

def test_find_equivalent_patterns():
    search_pattern = "[a:b=1]"
    other_patterns = [
        "[a:b=2]",
        "[a:b=1]",
        "[a:b=1] WITHIN 1 SECONDS",
        "[a:b=1] OR ([a:b=2] AND [a:b=1])",
        "[(a:b=2 OR a:b=1) AND a:b=1]",
        "[c:d=1]",
        "[a:b>1]",
    ]

    result = list(
        find_equivalent_patterns(search_pattern, other_patterns),
    )

    assert result == [
        "[a:b=1]",
        "[a:b=1] OR ([a:b=2] AND [a:b=1])",
        "[(a:b=2 OR a:b=1) AND a:b=1]",
    ]
