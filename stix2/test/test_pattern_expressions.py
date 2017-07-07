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
    exp1 = stix2.MatchesComparisonExpression("email-message:from_ref.value",
                                             stix2.StringConstant(".+\\@example\\.com$"))
    exp2 = stix2.MatchesComparisonExpression("email-message:body_multipart[*].body_raw_ref.name",
                                             stix2.StringConstant("^Final Report.+\\.exe$"))
    exp = stix2.ParentheticalExpression(stix2.AndBooleanExpression([exp1, exp2]))
    assert str(exp) == "(email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$')"  # noqa


def test_hash_followed_by_registryKey_expression():
    hash_exp = stix2.EqualityComparisonExpression("file:hashes.MD5",
                                                  stix2.HashConstant("79054025255fb1a26e4bc422aef54eb4", "MD5"))
    o_exp1 = stix2.ObservableExpression(hash_exp)
    reg_exp = stix2.EqualityComparisonExpression("win-registry-key:key",
                                                 stix2.StringConstant("HKEY_LOCAL_MACHINE\\foo\\bar"))
    o_exp2 = stix2.ObservableExpression(reg_exp)
    fb_exp = stix2.FollowedByObservableExpression([o_exp1, o_exp2])
    para_exp = stix2.ParentheticalExpression(fb_exp)
    qual_exp = stix2.WithinQualifier(stix2.IntegerConstant(300))
    exp = stix2.QualifiedObservationExpression(para_exp, qual_exp)
    assert str(exp) == "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [win-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS"  # noqa


def test_file_observable_expression():
    exp1 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              stix2.HashConstant(
                                                  "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
                                                  'SHA-256'))
    exp2 = stix2.EqualityComparisonExpression("file:mime_type", stix2.StringConstant("application/x-pdf"))
    bool_exp = stix2.AndBooleanExpression([exp1, exp2])
    exp = stix2.ObservableExpression(bool_exp)
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
    op1_exp = stix2.ObservableExpression(bool1_exp)
    op2_exp = stix2.ObservableExpression(exp3)
    exp = stix2.AndObservableExpression([op1_exp, op2_exp])
    assert str(exp) == "[file:hashes.'SHA-256' = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c' OR file:hashes.MD5 = 'cead3f77f6cda6ec00f57d76c9a6879f'] AND [file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']" # noqa


def test_root_types():
    ast = stix2.ObservableExpression(
            stix2.AndBooleanExpression(
                [stix2.ParentheticalExpression(
                    stix2.OrBooleanExpression([
                        stix2.EqualityComparisonExpression("a:b", stix2.StringConstant("1")),
                        stix2.EqualityComparisonExpression("b:c", stix2.StringConstant("2"))])),
                 stix2.EqualityComparisonExpression(u"b:d", stix2.StringConstant("3"))]))
    assert str(ast) == "[(a:b = '1' OR b:c = '2') AND b:d = '3']"


def test_artifact_payload():
    exp1 = stix2.EqualityComparisonExpression("artifact:mime_type",
                                              stix2.StringConstant("application/vnd.tcpdump.pcap"))
    exp2 = stix2.MatchesComparisonExpression("artifact:payload_bin",
                                             stix2.StringConstant("\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00"))
    and_exp = stix2.AndBooleanExpression([exp1, exp2])
    exp = stix2.ObservableExpression(and_exp)
    assert str(exp) == "[artifact:mime_type = 'application/vnd.tcpdump.pcap' AND artifact:payload_bin MATCHES '\\\\xd4\\\\xc3\\\\xb2\\\\xa1\\\\x02\\\\x00\\\\x04\\\\x00']"  # noqa


def test_greater_than():
    exp1 = stix2.GreaterThanComparisonExpression("file:extensions.windows-pebinary-ext.sections[*].entropy",
                                                 stix2.FloatConstant(7.0))
    exp = stix2.ObservableExpression(exp1)
    assert str(exp) == "[file:extensions.windows-pebinary-ext.sections[*].entropy > 7.0]"
