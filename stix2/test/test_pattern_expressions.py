import stix2


def test_create_comparison_expression():

    exp = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                             stix2.HashConstant("aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f", "SHA-256"))   # noqa
    assert str(exp) == "file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'"


def test_boolean_expression():
    exp1 = stix2.MatchesComparisonExpression("email-message:from_ref.value",
                                             stix2.StringConstant(".+\\@example\\.com$"))
    exp2 = stix2.MatchesComparisonExpression("email-message:body_multipart[*].body_raw_ref.name",
                                             stix2.StringConstant("^Final Report.+\\.exe$"))
    exp = stix2.AndBooleanExpression([exp1, exp2])
    assert str(exp) == "email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$'"  # noqa


def test_boolean_expression_with_parentheses():
    exp1 = stix2.MatchesComparisonExpression(stix2.ObjectPath("email-message",
                                                              [stix2.ReferenceObjectPathComponent("from_ref"),
                                                               stix2.BasicObjectPathComponent("value")]),
                                             stix2.StringConstant(".+\\@example\\.com$"))
    exp2 = stix2.MatchesComparisonExpression("email-message:body_multipart[*].body_raw_ref.name",
                                             stix2.StringConstant("^Final Report.+\\.exe$"))
    exp = stix2.ParentheticalExpression(stix2.AndBooleanExpression([exp1, exp2]))
    assert str(exp) == "(email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$')"  # noqa


def test_hash_followed_by_registryKey_expression_python_constant():
    hash_exp = stix2.EqualityComparisonExpression("file:hashes.MD5",
                                                  stix2.HashConstant("79054025255fb1a26e4bc422aef54eb4", "MD5"))
    o_exp1 = stix2.ObservationExpression(hash_exp)
    reg_exp = stix2.EqualityComparisonExpression(stix2.ObjectPath("windows-registry-key", ["key"]),
                                                 stix2.StringConstant("HKEY_LOCAL_MACHINE\\foo\\bar"))
    o_exp2 = stix2.ObservationExpression(reg_exp)
    fb_exp = stix2.FollowedByObservationExpression([o_exp1, o_exp2])
    para_exp = stix2.ParentheticalExpression(fb_exp)
    qual_exp = stix2.WithinQualifier(300)
    exp = stix2.QualifiedObservationExpression(para_exp, qual_exp)
    assert str(exp) == "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS"  # noqa


def test_hash_followed_by_registryKey_expression():
    hash_exp = stix2.EqualityComparisonExpression("file:hashes.MD5",
                                                  stix2.HashConstant("79054025255fb1a26e4bc422aef54eb4", "MD5"))
    o_exp1 = stix2.ObservationExpression(hash_exp)
    reg_exp = stix2.EqualityComparisonExpression(stix2.ObjectPath("windows-registry-key", ["key"]),
                                                 stix2.StringConstant("HKEY_LOCAL_MACHINE\\foo\\bar"))
    o_exp2 = stix2.ObservationExpression(reg_exp)
    fb_exp = stix2.FollowedByObservationExpression([o_exp1, o_exp2])
    para_exp = stix2.ParentheticalExpression(fb_exp)
    qual_exp = stix2.WithinQualifier(stix2.IntegerConstant(300))
    exp = stix2.QualifiedObservationExpression(para_exp, qual_exp)
    assert str(exp) == "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS"  # noqa


def test_file_observable_expression():
    exp1 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              stix2.HashConstant(
                                                  "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
                                                  'SHA-256'))
    exp2 = stix2.EqualityComparisonExpression("file:mime_type", stix2.StringConstant("application/x-pdf"))
    bool_exp = stix2.AndBooleanExpression([exp1, exp2])
    exp = stix2.ObservationExpression(bool_exp)
    assert str(exp) == "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file:mime_type = 'application/x-pdf']"  # noqa


def test_multiple_file_observable_expression():
    exp1 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              stix2.HashConstant(
                                                  "bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c",
                                                  'SHA-256'))
    exp2 = stix2.EqualityComparisonExpression("file:hashes.MD5",
                                              stix2.HashConstant("cead3f77f6cda6ec00f57d76c9a6879f", "MD5"))
    bool1_exp = stix2.OrBooleanExpression([exp1, exp2])
    exp3 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              stix2.HashConstant(
                                                  "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
                                                  'SHA-256'))
    op1_exp = stix2.ObservationExpression(bool1_exp)
    op2_exp = stix2.ObservationExpression(exp3)
    exp = stix2.AndObservationExpression([op1_exp, op2_exp])
    assert str(exp) == "[file:hashes.'SHA-256' = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c' OR file:hashes.MD5 = 'cead3f77f6cda6ec00f57d76c9a6879f'] AND [file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"  # noqa


def test_root_types():
    ast = stix2.ObservationExpression(
            stix2.AndBooleanExpression(
                [stix2.ParentheticalExpression(
                    stix2.OrBooleanExpression([
                        stix2.EqualityComparisonExpression("a:b", stix2.StringConstant("1")),
                        stix2.EqualityComparisonExpression("b:c", stix2.StringConstant("2"))])),
                 stix2.EqualityComparisonExpression(u"b:d", stix2.StringConstant("3"))]))
    assert str(ast) == "[(a:b = '1' OR b:c = '2') AND b:d = '3']"


def test_artifact_payload():
    exp1 = stix2.EqualityComparisonExpression("artifact:mime_type",
                                              "application/vnd.tcpdump.pcap")
    exp2 = stix2.MatchesComparisonExpression("artifact:payload_bin",
                                             stix2.StringConstant("\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00"))
    and_exp = stix2.AndBooleanExpression([exp1, exp2])
    exp = stix2.ObservationExpression(and_exp)
    assert str(exp) == "[artifact:mime_type = 'application/vnd.tcpdump.pcap' AND artifact:payload_bin MATCHES '\\\\xd4\\\\xc3\\\\xb2\\\\xa1\\\\x02\\\\x00\\\\x04\\\\x00']"  # noqa


def test_greater_than_python_constant():
    exp1 = stix2.GreaterThanComparisonExpression("file:extensions.windows-pebinary-ext.sections[*].entropy",
                                                 7.0)
    exp = stix2.ObservationExpression(exp1)
    assert str(exp) == "[file:extensions.windows-pebinary-ext.sections[*].entropy > 7.0]"


def test_greater_than():
    exp1 = stix2.GreaterThanComparisonExpression("file:extensions.windows-pebinary-ext.sections[*].entropy",
                                                 stix2.FloatConstant(7.0))
    exp = stix2.ObservationExpression(exp1)
    assert str(exp) == "[file:extensions.windows-pebinary-ext.sections[*].entropy > 7.0]"


def test_and_observable_expression():
    exp1 = stix2.AndBooleanExpression([stix2.EqualityComparisonExpression("user-account:account_type",
                                                                          "unix"),
                                       stix2.EqualityComparisonExpression("user-account:user_id",
                                                                          stix2.StringConstant("1007")),
                                       stix2.EqualityComparisonExpression("user-account:account_login",
                                                                          "Peter")])
    exp2 = stix2.AndBooleanExpression([stix2.EqualityComparisonExpression("user-account:account_type",
                                                                          "unix"),
                                       stix2.EqualityComparisonExpression("user-account:user_id",
                                                                          stix2.StringConstant("1008")),
                                       stix2.EqualityComparisonExpression("user-account:account_login",
                                                                          "Paul")])
    exp3 = stix2.AndBooleanExpression([stix2.EqualityComparisonExpression("user-account:account_type",
                                                                          "unix"),
                                       stix2.EqualityComparisonExpression("user-account:user_id",
                                                                          stix2.StringConstant("1009")),
                                       stix2.EqualityComparisonExpression("user-account:account_login",
                                                                          "Mary")])
    exp = stix2.AndObservationExpression([stix2.ObservationExpression(exp1),
                                         stix2.ObservationExpression(exp2),
                                         stix2.ObservationExpression(exp3)])
    assert str(exp) == "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']"  # noqa


def test_hex():
    exp_and = stix2.AndBooleanExpression([stix2.EqualityComparisonExpression("file:mime_type",
                                                                             "image/bmp"),
                                          stix2.EqualityComparisonExpression("file:magic_number_hex",
                                                                             stix2.HexConstant("ffd8"))])
    exp = stix2.ObservationExpression(exp_and)
    assert str(exp) == "[file:mime_type = 'image/bmp' AND file:magic_number_hex = h'ffd8']"


def test_multiple_qualifiers():
    exp_and = stix2.AndBooleanExpression([stix2.EqualityComparisonExpression("network-traffic:dst_ref.type",
                                                                             "domain-name"),
                                          stix2.EqualityComparisonExpression("network-traffic:dst_ref.value",
                                                                             "example.com")])
    exp_ob = stix2.ObservationExpression(exp_and)
    qual_rep = stix2.RepeatQualifier(5)
    qual_within = stix2.WithinQualifier(stix2.IntegerConstant(1800))
    exp = stix2.QualifiedObservationExpression(stix2.QualifiedObservationExpression(exp_ob, qual_rep), qual_within)
    assert str(exp) == "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 5 TIMES WITHIN 1800 SECONDS"  # noqa


def test_set_op():
    exp = stix2.ObservationExpression(stix2.IsSubsetComparisonExpression("network-traffic:dst_ref.value",
                                                                         "2001:0db8:dead:beef:0000:0000:0000:0000/64"))
    assert str(exp) == "[network-traffic:dst_ref.value ISSUBSET '2001:0db8:dead:beef:0000:0000:0000:0000/64']"


def test_timestamp():
    ts = stix2.TimestampConstant('2014-01-13T07:03:17Z')
    assert str(ts) == "t'2014-01-13T07:03:17Z'"
