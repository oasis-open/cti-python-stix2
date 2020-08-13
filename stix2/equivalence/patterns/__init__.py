import stix2.pattern_visitor
from stix2.equivalence.patterns.transform import (
    ChainTransformer, SettleTransformer
)
from stix2.equivalence.patterns.compare.observation import (
    observation_expression_cmp
)
from stix2.equivalence.patterns.transform.observation import (
    CanonicalizeComparisonExpressionsTransformer,
    AbsorptionTransformer,
    FlattenTransformer,
    DNFTransformer,
    OrderDedupeTransformer
)


# Lazy-initialize
_pattern_canonicalizer = None


def _get_pattern_canonicalizer():
    """
    Get a canonicalization transformer for STIX patterns.

    :return: The transformer
    """

    # The transformers are either stateless or contain no state which changes
    # with each use.  So we can setup the transformers once and keep reusing
    # them.
    global _pattern_canonicalizer

    if not _pattern_canonicalizer:
        canonicalize_comp_expr = \
            CanonicalizeComparisonExpressionsTransformer()

        obs_expr_flatten = FlattenTransformer()
        obs_expr_order = OrderDedupeTransformer()
        obs_expr_absorb = AbsorptionTransformer()
        obs_simplify = ChainTransformer(
            obs_expr_flatten, obs_expr_order, obs_expr_absorb
        )
        obs_settle_simplify = SettleTransformer(obs_simplify)

        obs_dnf = DNFTransformer()

        _pattern_canonicalizer = ChainTransformer(
            canonicalize_comp_expr,
            obs_settle_simplify, obs_dnf, obs_settle_simplify
        )

    return _pattern_canonicalizer


def equivalent_patterns(pattern1, pattern2):
    """
    Determine whether two STIX patterns are semantically equivalent.

    :param pattern1: The first STIX pattern
    :param pattern2: The second STIX pattern
    :return: True if the patterns are semantically equivalent; False if not
    """
    patt_ast1 = stix2.pattern_visitor.create_pattern_object(pattern1)
    patt_ast2 = stix2.pattern_visitor.create_pattern_object(pattern2)

    pattern_canonicalizer = _get_pattern_canonicalizer()
    canon_patt1, _ = pattern_canonicalizer.transform(patt_ast1)
    canon_patt2, _ = pattern_canonicalizer.transform(patt_ast2)

    result = observation_expression_cmp(canon_patt1, canon_patt2)

    return result == 0


def find_equivalent_patterns(search_pattern, patterns):
    """
    Find patterns from a sequence which are equivalent to a given pattern.
    This is more efficient than using equivalent_patterns() in a loop, because
    it doesn't re-canonicalize the search pattern over and over.  This works
    on an input iterable and is implemented as a generator of matches.  So you
    can "stream" patterns in and matching patterns will be streamed out.

    :param search_pattern: A search pattern as a string
    :param patterns: An iterable over patterns as strings
    :return: A generator iterator producing the semantically equivalent
        patterns
    """
    search_pattern_ast = stix2.pattern_visitor.create_pattern_object(
        search_pattern
    )

    pattern_canonicalizer = _get_pattern_canonicalizer()
    canon_search_pattern_ast, _ = pattern_canonicalizer.transform(
        search_pattern_ast
    )

    for pattern in patterns:
        pattern_ast = stix2.pattern_visitor.create_pattern_object(pattern)
        canon_pattern_ast, _ = pattern_canonicalizer.transform(pattern_ast)

        result = observation_expression_cmp(
            canon_search_pattern_ast, canon_pattern_ast
        )

        if result == 0:
            yield pattern
