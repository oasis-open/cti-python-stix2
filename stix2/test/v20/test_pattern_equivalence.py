"""
Pattern equivalence unit tests which use STIX 2.0-specific pattern features
"""

import pytest

from stix2.equivalence.patterns import equivalent_patterns


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b=1] START '1993-06-29T15:24:42Z' STOP '2000-07-30T19:29:58Z'",
            "[a:b=1 OR (a:c=2 AND a:b=1)] START '1993-06-29T15:24:42Z' STOP '2000-07-30T19:29:58Z'",
        ),
        (
            "[a:b=1] START '1993-06-29T15:24:42Z' STOP '2000-07-30T19:29:58Z' WITHIN 2 SECONDS",
            "[a:b=1 OR (a:c=2 AND a:b=1)] START '1993-06-29T15:24:42Z' STOP '2000-07-30T19:29:58Z' WITHIN 2 SECONDS",
        ),
        (
            "[a:b=1] REPEATS 2 TIMES REPEATS 2 TIMES",
            "([a:b=1] REPEATS 2 TIMES) REPEATS 2 TIMES",
        ),
    ],
)
def test_startstop_equivalent(patt1, patt2):
    assert equivalent_patterns(patt1, patt2, stix_version="2.0")


@pytest.mark.parametrize(
    "patt1, patt2", [
        (
            "[a:b!=1] START '1993-06-29T15:24:42Z' STOP '2000-07-30T19:29:58Z'",
            "[a:b!=1] START '1977-09-29T07:41:03Z' STOP '1996-09-18T22:46:07Z'",
        ),
        (
            "[a:b<1] REPEATS 2 TIMES START '1993-06-29T15:24:42Z' STOP '2000-07-30T19:29:58Z'",
            "[a:b<1] REPEATS 2 TIMES START '1977-09-29T07:41:03Z' STOP '1996-09-18T22:46:07Z'",
        ),
        (
            "[a:b=1] REPEATS 2 TIMES REPEATS 2 TIMES",
            "([a:b=1] REPEATS 2 TIMES) REPEATS 3 TIMES",
        ),
    ],
)
def test_startstop_not_equivalent(patt1, patt2):
    assert not equivalent_patterns(patt1, patt2, stix_version="2.0")
