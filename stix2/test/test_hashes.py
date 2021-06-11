import pytest

from stix2.hashes import Hash, check_hash, infer_hash_algorithm


@pytest.mark.parametrize(
    "hash_name, expected_alg", [
        ("md5", Hash.MD5),
        ("md6", Hash.MD6),
        ("ripemd160", Hash.RIPEMD160),
        ("sha1", Hash.SHA1),
        ("sha224", Hash.SHA224),
        ("sha256", Hash.SHA256),
        ("sha384", Hash.SHA384),
        ("sha512", Hash.SHA512),
        ("sha3224", Hash.SHA3224),
        ("sha3256", Hash.SHA3256),
        ("sha3384", Hash.SHA3384),
        ("sha3512", Hash.SHA3512),
        ("ssdeep", Hash.SSDEEP),
        ("whirlpool", Hash.WHIRLPOOL),
        ("tlsh", Hash.TLSH),
        ("xxxx", None),
    ],
)
def test_hash_inference(hash_name, expected_alg):
    alg = infer_hash_algorithm(hash_name)
    assert alg == expected_alg

    # Try some other name variations
    alg = infer_hash_algorithm(hash_name[0].upper() + hash_name[1:])
    assert alg == expected_alg

    alg = infer_hash_algorithm("-"+hash_name)
    assert alg == expected_alg


@pytest.mark.parametrize(
    "hash_alg, hash_value", [
        (Hash.MD5, "f9e40b9aa5464f3dae711ca524fceb63"),
        (Hash.MD6, "f9e40b9aa5464f3dae711ca524fceb63"),
        (Hash.RIPEMD160, "8ae5d2e6b1f3a514257f2469b637454931844aeb"),
        (Hash.SHA1, "f2c7d4185880c0adcbb4a01d020a69498b16210e"),
        (Hash.SHA224, "6743ed70cc26e750ad0108b6b8ad7fc2780c550f7d78adefa04dda05"),
        (Hash.SHA256, "a2d1c2081aa932fe72307ab076b9739455bc7a21b3bed367bd9a86ae27af5a40"),
        (Hash.SHA384, "bc846457de707f97bce93cca23b5ea58c0326fd8b79ef7b523ba1d0a792f22868732e53a5dcf2f9e3b89eecca9c9b4e3"),
        (Hash.SHA512, "896e45c82f9d8ba917d4f95891c967b88304b0a67ccc59aac813ee7ab3bc700bf9ce559e283c35ddba619755f6b70bdff2a07dc9cd337576a143a2aa361d08b1"),
        (Hash.SHA3224, "37cb283bc9f6ecf0f94e92d5bd4c1e061ae00d7ed85804d18f981f53"),
        (Hash.SHA3256, "d5fc146e37d4fddaeaa57aa88390be5c9ca6bcb18ae1bf2346cbfc36d3310ea2"),
        (Hash.SHA3384, "ac97414589b2ef59a87dc5277d156b6cfc8f6b92b7c0e889d8f38a235dd9c1ba4030321beddd13f29519390ba914f70f"),
        (Hash.SHA3512, "8dc580ad3abc6305ce5ada7c5920c763720c7733c2a94d28dd5351ffbc162b6b6d21371d91d6559124159025172e19896e09889047aac4ef555cc55456e14b0a"),
        (Hash.SSDEEP, "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"),
        (Hash.WHIRLPOOL, "b752b6eeb497a8bebfc1be1649ca41d57fd1973bffc2261ca196b5474e0f353762f354c1d743581f61c51f4d86921360bc2e8ad35e830578b68b12e884a50894"),
        (Hash.TLSH, "6FF02BEF718027B0160B4391212923ED7F1A463D563B1549B86CF62973B197AD2731F8"),
        ("foo", "bar"),  # unrecognized hash type is accepted as-is
    ],
)
def test_hash_check(hash_alg, hash_value):
    assert check_hash(hash_alg, hash_value)
    assert check_hash(hash_alg, hash_value.upper())  # check case sensitivity


def test_hash_check_fail():
    for hash_alg in Hash:
        assert not check_hash(hash_alg, "x"*200)
