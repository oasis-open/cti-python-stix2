import datetime

import pytest

import stix2
from stix2.pattern_visitor import create_pattern_object


def test_create_comparison_expression():
    exp = stix2.EqualityComparisonExpression(
        "file:hashes.'SHA-256'",
        stix2.HashConstant("aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f", "SHA-256"),
    )   # noqa

    assert str(exp) == "file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'"


def test_boolean_expression():
    exp1 = stix2.MatchesComparisonExpression(
        "email-message:from_ref.value",
        stix2.StringConstant(".+\\@example\\.com$"),
    )
    exp2 = stix2.MatchesComparisonExpression(
        "email-message:body_multipart[*].body_raw_ref.name",
        stix2.StringConstant("^Final Report.+\\.exe$"),
    )
    exp = stix2.AndBooleanExpression([exp1, exp2])

    assert str(exp) == "email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$'"  # noqa


def test_boolean_expression_with_parentheses():
    exp1 = stix2.MatchesComparisonExpression(
        stix2.ObjectPath(
            "email-message",
            [
                stix2.ReferenceObjectPathComponent("from_ref"),
                stix2.BasicObjectPathComponent("value", False),
            ],
        ),
        stix2.StringConstant(".+\\@example\\.com$"),
    )
    exp2 = stix2.MatchesComparisonExpression(
        "email-message:body_multipart[*].body_raw_ref.name",
        stix2.StringConstant("^Final Report.+\\.exe$"),
    )
    exp = stix2.ParentheticalExpression(stix2.AndBooleanExpression([exp1, exp2]))
    assert str(exp) == "(email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$')"  # noqa


def test_hash_followed_by_registryKey_expression_python_constant():
    hash_exp = stix2.EqualityComparisonExpression(
        "file:hashes.MD5",
        stix2.HashConstant("79054025255fb1a26e4bc422aef54eb4", "MD5"),
    )
    o_exp1 = stix2.ObservationExpression(hash_exp)
    reg_exp = stix2.EqualityComparisonExpression(
        stix2.ObjectPath("windows-registry-key", ["key"]),
        stix2.StringConstant("HKEY_LOCAL_MACHINE\\foo\\bar"),
    )
    o_exp2 = stix2.ObservationExpression(reg_exp)
    fb_exp = stix2.FollowedByObservationExpression([o_exp1, o_exp2])
    para_exp = stix2.ParentheticalExpression(fb_exp)
    qual_exp = stix2.WithinQualifier(300)
    exp = stix2.QualifiedObservationExpression(para_exp, qual_exp)
    assert str(exp) == "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS"  # noqa


def test_hash_followed_by_registryKey_expression():
    hash_exp = stix2.EqualityComparisonExpression(
        "file:hashes.MD5",
        stix2.HashConstant("79054025255fb1a26e4bc422aef54eb4", "MD5"),
    )
    o_exp1 = stix2.ObservationExpression(hash_exp)
    reg_exp = stix2.EqualityComparisonExpression(
        stix2.ObjectPath("windows-registry-key", ["key"]),
        stix2.StringConstant("HKEY_LOCAL_MACHINE\\foo\\bar"),
    )
    o_exp2 = stix2.ObservationExpression(reg_exp)
    fb_exp = stix2.FollowedByObservationExpression([o_exp1, o_exp2])
    para_exp = stix2.ParentheticalExpression(fb_exp)
    qual_exp = stix2.WithinQualifier(stix2.IntegerConstant(300))
    exp = stix2.QualifiedObservationExpression(para_exp, qual_exp)
    assert str(exp) == "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS"  # noqa


def test_file_observable_expression():
    exp1 = stix2.EqualityComparisonExpression(
        "file:hashes.'SHA-256'",
        stix2.HashConstant(
            "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
            'SHA-256',
        ),
    )
    exp2 = stix2.EqualityComparisonExpression("file:mime_type", stix2.StringConstant("application/x-pdf"))
    bool_exp = stix2.ObservationExpression(stix2.AndBooleanExpression([exp1, exp2]))
    assert str(bool_exp) == "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file:mime_type = 'application/x-pdf']"  # noqa


@pytest.mark.parametrize(
    "observation_class, op", [
        (stix2.AndObservationExpression, 'AND'),
        (stix2.OrObservationExpression, 'OR'),
    ],
)
def test_multiple_file_observable_expression(observation_class, op):
    exp1 = stix2.EqualityComparisonExpression(
        "file:hashes.'SHA-256'",
        stix2.HashConstant(
            "bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c",
            'SHA-256',
        ),
    )
    exp2 = stix2.EqualityComparisonExpression(
        "file:hashes.MD5",
        stix2.HashConstant("cead3f77f6cda6ec00f57d76c9a6879f", "MD5"),
    )
    bool1_exp = stix2.OrBooleanExpression([exp1, exp2])
    exp3 = stix2.EqualityComparisonExpression(
        "file:hashes.'SHA-256'",
        stix2.HashConstant(
            "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
            'SHA-256',
        ),
    )
    op1_exp = stix2.ObservationExpression(bool1_exp)
    op2_exp = stix2.ObservationExpression(exp3)
    exp = observation_class([op1_exp, op2_exp])
    assert str(exp) == "[file:hashes.'SHA-256' = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c' OR file:hashes.MD5 = 'cead3f77f6cda6ec00f57d76c9a6879f'] {} [file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']".format(op)  # noqa


def test_root_types():
    ast = stix2.ObservationExpression(
            stix2.AndBooleanExpression(
                [
                    stix2.ParentheticalExpression(
                       stix2.OrBooleanExpression([
                           stix2.EqualityComparisonExpression("a:b", stix2.StringConstant("1")),
                           stix2.EqualityComparisonExpression("b:c", stix2.StringConstant("2")),
                       ]),
                    ),
                    stix2.EqualityComparisonExpression(u"b:d", stix2.StringConstant("3")),
                ],
            ),
    )
    assert str(ast) == "[(a:b = '1' OR b:c = '2') AND b:d = '3']"


def test_artifact_payload():
    exp1 = stix2.EqualityComparisonExpression(
        "artifact:mime_type",
        "application/vnd.tcpdump.pcap",
    )
    exp2 = stix2.MatchesComparisonExpression(
        "artifact:payload_bin",
        stix2.StringConstant("\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00"),
    )
    and_exp = stix2.ObservationExpression(stix2.AndBooleanExpression([exp1, exp2]))
    assert str(and_exp) == "[artifact:mime_type = 'application/vnd.tcpdump.pcap' AND artifact:payload_bin MATCHES '\\\\xd4\\\\xc3\\\\xb2\\\\xa1\\\\x02\\\\x00\\\\x04\\\\x00']"  # noqa


def test_greater_than_python_constant():
    exp1 = stix2.GreaterThanComparisonExpression("file:extensions.'windows-pebinary-ext'.sections[*].entropy", 7.0)
    exp = stix2.ObservationExpression(exp1)
    assert str(exp) == "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.0]"


def test_greater_than():
    exp1 = stix2.GreaterThanComparisonExpression(
        "file:extensions.'windows-pebinary-ext'.sections[*].entropy",
        stix2.FloatConstant(7.0),
    )
    exp = stix2.ObservationExpression(exp1)
    assert str(exp) == "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.0]"


def test_less_than():
    exp = stix2.LessThanComparisonExpression("file:size", 1024)
    assert str(exp) == "file:size < 1024"


def test_greater_than_or_equal():
    exp = stix2.GreaterThanEqualComparisonExpression(
        "file:size",
        1024,
    )

    assert str(exp) == "file:size >= 1024"


def test_less_than_or_equal():
    exp = stix2.LessThanEqualComparisonExpression(
        "file:size",
        1024,
    )
    assert str(exp) == "file:size <= 1024"


def test_not():
    exp = stix2.LessThanComparisonExpression(
        "file:size",
        1024,
        negated=True,
    )
    assert str(exp) == "file:size NOT < 1024"


def test_and_observable_expression():
    exp1 = stix2.AndBooleanExpression([
        stix2.EqualityComparisonExpression(
            "user-account:account_type",
            "unix",
        ),
        stix2.EqualityComparisonExpression(
            "user-account:user_id",
            stix2.StringConstant("1007"),
        ),
        stix2.EqualityComparisonExpression(
            "user-account:account_login",
            "Peter",
        ),
    ])
    exp2 = stix2.AndBooleanExpression([
        stix2.EqualityComparisonExpression(
            "user-account:account_type",
            "unix",
        ),
        stix2.EqualityComparisonExpression(
            "user-account:user_id",
            stix2.StringConstant("1008"),
        ),
        stix2.EqualityComparisonExpression(
            "user-account:account_login",
            "Paul",
        ),
    ])
    exp3 = stix2.AndBooleanExpression([
        stix2.EqualityComparisonExpression(
            "user-account:account_type",
            "unix",
        ),
        stix2.EqualityComparisonExpression(
            "user-account:user_id",
            stix2.StringConstant("1009"),
        ),
        stix2.EqualityComparisonExpression(
            "user-account:account_login",
            "Mary",
        ),
    ])
    exp = stix2.AndObservationExpression([
        stix2.ObservationExpression(exp1),
        stix2.ObservationExpression(exp2),
        stix2.ObservationExpression(exp3),
    ])
    assert str(exp) == "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']"  # noqa


def test_invalid_and_observable_expression():
    with pytest.raises(ValueError) as excinfo:
        stix2.AndBooleanExpression([
            stix2.EqualityComparisonExpression(
                "user-account:display_name",
                "admin",
            ),
            stix2.EqualityComparisonExpression(
                "email-addr:display_name",
                stix2.StringConstant("admin"),
            ),
        ])
    assert "All operands to an 'AND' expression must have the same object type" in str(excinfo)


def test_hex():
    exp_and = stix2.AndBooleanExpression([
        stix2.EqualityComparisonExpression(
            "file:mime_type",
            "image/bmp",
        ),
        stix2.EqualityComparisonExpression(
            "file:magic_number_hex",
            stix2.HexConstant("ffd8"),
        ),
    ])
    exp = stix2.ObservationExpression(exp_and)
    assert str(exp) == "[file:mime_type = 'image/bmp' AND file:magic_number_hex = h'ffd8']"


def test_multiple_qualifiers():
    exp_and = stix2.AndBooleanExpression([
        stix2.EqualityComparisonExpression(
            "network-traffic:dst_ref.type",
            "domain-name",
        ),
        stix2.EqualityComparisonExpression(
            "network-traffic:dst_ref.value",
            "example.com",
        ),
    ])
    exp_ob = stix2.ObservationExpression(exp_and)
    qual_rep = stix2.RepeatQualifier(5)
    qual_within = stix2.WithinQualifier(stix2.IntegerConstant(1800))
    exp = stix2.QualifiedObservationExpression(stix2.QualifiedObservationExpression(exp_ob, qual_rep), qual_within)
    assert str(exp) == "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 5 TIMES WITHIN 1800 SECONDS"  # noqa


def test_set_op():
    exp = stix2.ObservationExpression(stix2.IsSubsetComparisonExpression(
        "network-traffic:dst_ref.value",
        "2001:0db8:dead:beef:0000:0000:0000:0000/64",
    ))
    assert str(exp) == "[network-traffic:dst_ref.value ISSUBSET '2001:0db8:dead:beef:0000:0000:0000:0000/64']"


def test_timestamp():
    ts = stix2.TimestampConstant('2014-01-13T07:03:17Z')
    assert str(ts) == "t'2014-01-13T07:03:17Z'"


def test_boolean():
    exp = stix2.EqualityComparisonExpression(
        "email-message:is_multipart",
        True,
    )
    assert str(exp) == "email-message:is_multipart = true"


def test_binary():
    const = stix2.BinaryConstant("dGhpcyBpcyBhIHRlc3Q=")
    exp = stix2.EqualityComparisonExpression(
        "artifact:payload_bin",
        const,
    )
    assert str(exp) == "artifact:payload_bin = b'dGhpcyBpcyBhIHRlc3Q='"


def test_list():
    exp = stix2.InComparisonExpression(
        "process:name",
        ['proccy', 'proximus', 'badproc'],
    )
    assert str(exp) == "process:name IN ('proccy', 'proximus', 'badproc')"


def test_list2():
    # alternate way to construct an "IN" Comparison Expression
    exp = stix2.EqualityComparisonExpression(
        "process:name",
        ['proccy', 'proximus', 'badproc'],
    )
    assert str(exp) == "process:name IN ('proccy', 'proximus', 'badproc')"


def test_invalid_constant_type():
    with pytest.raises(ValueError) as excinfo:
        stix2.EqualityComparisonExpression(
            "artifact:payload_bin",
            {'foo': 'bar'},
        )
    assert 'Unable to create a constant' in str(excinfo)


def test_invalid_integer_constant():
    with pytest.raises(ValueError) as excinfo:
        stix2.IntegerConstant('foo')
    assert 'must be an integer' in str(excinfo)


def test_invalid_timestamp_constant():
    with pytest.raises(ValueError) as excinfo:
        stix2.TimestampConstant('foo')
    assert 'Must be a datetime object or timestamp string' in str(excinfo)


def test_invalid_float_constant():
    with pytest.raises(ValueError) as excinfo:
        stix2.FloatConstant('foo')
    assert 'must be a float' in str(excinfo)


@pytest.mark.parametrize(
    "data, result", [
        (True, True),
        (False, False),
        ('True', True),
        ('False', False),
        ('true', True),
        ('false', False),
        ('t', True),
        ('f', False),
        ('T', True),
        ('F', False),
        (1, True),
        (0, False),
    ],
)
def test_boolean_constant(data, result):
    boolean = stix2.BooleanConstant(data)
    assert boolean.value == result


def test_invalid_boolean_constant():
    with pytest.raises(ValueError) as excinfo:
        stix2.BooleanConstant('foo')
    assert 'must be a boolean' in str(excinfo)


@pytest.mark.parametrize(
    "hashtype, data", [
        ('MD5', 'zzz'),
        ('ssdeep', 'zzz=='),
    ],
)
def test_invalid_hash_constant(hashtype, data):
    with pytest.raises(ValueError) as excinfo:
        stix2.HashConstant(data, hashtype)
    assert 'is not a valid {} hash'.format(hashtype) in str(excinfo)


def test_invalid_hex_constant():
    with pytest.raises(ValueError) as excinfo:
        stix2.HexConstant('mm')
    assert "must contain an even number of hexadecimal characters" in str(excinfo)


def test_invalid_binary_constant():
    with pytest.raises(ValueError) as excinfo:
        stix2.BinaryConstant('foo')
    assert 'must contain a base64' in str(excinfo)


def test_escape_quotes_and_backslashes():
    exp = stix2.MatchesComparisonExpression(
        "file:name",
        "^Final Report.+\\.exe$",
    )
    assert str(exp) == "file:name MATCHES '^Final Report.+\\\\.exe$'"


def test_like():
    exp = stix2.LikeComparisonExpression(
        "directory:path",
        "C:\\Windows\\%\\foo",
    )
    assert str(exp) == "directory:path LIKE 'C:\\\\Windows\\\\%\\\\foo'"


def test_issuperset():
    exp = stix2.IsSupersetComparisonExpression(
        "ipv4-addr:value",
        "198.51.100.0/24",
    )
    assert str(exp) == "ipv4-addr:value ISSUPERSET '198.51.100.0/24'"


def test_repeat_qualifier():
    qual = stix2.RepeatQualifier(stix2.IntegerConstant(5))
    assert str(qual) == 'REPEATS 5 TIMES'


def test_invalid_repeat_qualifier():
    with pytest.raises(ValueError) as excinfo:
        stix2.RepeatQualifier('foo')
    assert 'is not a valid argument for a Repeat Qualifier' in str(excinfo)


def test_invalid_within_qualifier():
    with pytest.raises(ValueError) as excinfo:
        stix2.WithinQualifier('foo')
    assert 'is not a valid argument for a Within Qualifier' in str(excinfo)


def test_startstop_qualifier():
    qual = stix2.StartStopQualifier(
        stix2.TimestampConstant('2016-06-01T00:00:00Z'),
        datetime.datetime(2017, 3, 12, 8, 30, 0),
    )
    assert str(qual) == "START t'2016-06-01T00:00:00Z' STOP t'2017-03-12T08:30:00Z'"

    qual2 = stix2.StartStopQualifier(
        datetime.date(2016, 6, 1),
        stix2.TimestampConstant('2016-07-01T00:00:00Z'),
    )
    assert str(qual2) == "START t'2016-06-01T00:00:00Z' STOP t'2016-07-01T00:00:00Z'"


def test_invalid_startstop_qualifier():
    with pytest.raises(ValueError) as excinfo:
        stix2.StartStopQualifier(
            'foo',
            stix2.TimestampConstant('2016-06-01T00:00:00Z'),
        )
    assert 'is not a valid argument for a Start/Stop Qualifier' in str(excinfo)

    with pytest.raises(ValueError) as excinfo:
        stix2.StartStopQualifier(
            datetime.date(2016, 6, 1),
            'foo',
        )
    assert 'is not a valid argument for a Start/Stop Qualifier' in str(excinfo)


def test_make_constant_already_a_constant():
    str_const = stix2.StringConstant('Foo')
    result = stix2.patterns.make_constant(str_const)
    assert result is str_const


def test_parsing_comparison_expression():
    patt_obj = create_pattern_object("[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']")
    assert str(patt_obj) == "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"


def test_parsing_qualified_expression():
    patt_obj = create_pattern_object(
        "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 5 TIMES WITHIN 1800 SECONDS",
    )
    assert str(
        patt_obj,
    ) == "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 5 TIMES WITHIN 1800 SECONDS"


def test_list_constant():
    patt_obj = create_pattern_object("[network-traffic:src_ref.value IN ('10.0.0.0', '10.0.0.1', '10.0.0.2')]")
    assert str(patt_obj) == "[network-traffic:src_ref.value IN ('10.0.0.0', '10.0.0.1', '10.0.0.2')]"
