import stix2


def test_create_comparison_expression():

    exp = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'", "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f")
    assert str(exp) == "file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'"


def test_boolean_expression():
    exp1 = stix2.MatchesComparisonExpression("email-message:from_ref.value", ".+\\@example\\.com$")
    exp2 = stix2.MatchesComparisonExpression("email-message:body_multipart[*].body_raw_ref.name", "^Final Report.+\\.exe$")
    exp = stix2.AndBooleanExpression([exp1, exp2])
    assert str(exp) == "email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$'"  # noqa


def test_boolean_expression_with_parentheses():
    exp1 = stix2.MatchesComparisonExpression("email-message:from_ref.value", ".+\\@example\\.com$")
    exp2 = stix2.MatchesComparisonExpression("email-message:body_multipart[*].body_raw_ref.name", "^Final Report.+\\.exe$")
    exp = stix2.ParentheticalExpression(stix2.AndBooleanExpression([exp1, exp2]))
    assert str(exp) == "(email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$')"  # noqa


def test_hash_followed_by_registryKey_expression():
    hash_exp = stix2.EqualityComparisonExpression("file:hashes.MD5",
                                                  "79054025255fb1a26e4bc422aef54eb4")
    o_exp1 = stix2.ObservableExpression(hash_exp)
    reg_exp = stix2.EqualityComparisonExpression("win-registry-key:key",
                                                 "HKEY_LOCAL_MACHINE\\foo\\bar")
    o_exp2 = stix2.ObservableExpression(reg_exp)
    fb_exp = stix2.FollowedByObservableExpression([o_exp1, o_exp2])
    para_exp = stix2.ParentheticalExpression(fb_exp)
    qual_exp = stix2.WithinQualifier(300)
    exp = stix2.QualifiedObservationExpression(para_exp, qual_exp)
    assert str(exp) == "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [win-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS"  # noqa


def test_file_observable_expression():
    exp1 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f")
    exp2 = stix2.EqualityComparisonExpression("file:mime_type", "application/x-pdf")
    bool_exp = stix2.AndBooleanExpression([exp1, exp2])
    exp = stix2.ObservableExpression(bool_exp)
    assert str(exp) == "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file:mime_type = 'application/x-pdf']"  # noqa


def test_multiple_file_observable_expression():
    exp1 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              "bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c")
    exp2 = stix2.EqualityComparisonExpression("file:hashes.MD5",
                                              "cead3f77f6cda6ec00f57d76c9a6879f")
    bool1_exp = stix2.OrBooleanExpression([exp1, exp2])
    exp3 = stix2.EqualityComparisonExpression("file:hashes.'SHA-256'",
                                              "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f")
    op1_exp = stix2.ObservableExpression(bool1_exp)
    op2_exp = stix2.ObservableExpression(exp3)
    exp = stix2.AndObservableExpression([op1_exp, op2_exp])
    assert str(exp) == "[file:hashes.'SHA-256' = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c' OR file:hashes.MD5 = 'cead3f77f6cda6ec00f57d76c9a6879f'] AND [file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']" # noqa
