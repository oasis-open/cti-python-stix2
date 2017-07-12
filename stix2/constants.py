import base64
import binascii
import re

# TODO: REConstant?
# TODO: Timestamp


class Constant(object):
    def __str__(self):
        return "%s" % self.value

    @staticmethod
    def escape_quotes_and_backslashes(s):
        return s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")


class StringConstant(Constant):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "'%s'" % StringConstant.escape_quotes_and_backslashes(self.value)


class IntegerConstant(Constant):
    def __init__(self, value):
        try:
            self.value = int(value)
        except Exception:
            raise ValueError("must be an integer.")


class FloatConstant(Constant):
    def __init__(self, value):
        try:
            self.value = float(value)
        except Exception:
            raise ValueError("must be an float.")


class BooleanConstant(Constant):
    def __init__(self, value):
        if isinstance(value, bool):
            self.value = value

        trues = ['true', 't']
        falses = ['false', 'f']
        try:
            if value.lower() in trues:
                self.value = True
            if value.lower() in falses:
                self.value = False
        except AttributeError:
            if value == 1:
                self.value = True
            if value == 0:
                self.value = False

        raise ValueError("must be a boolean value.")


_HASH_REGEX = {
    "MD5": ("^[a-fA-F0-9]{32}$", "MD5"),
    "MD6": ("^[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}$", "MD6"),
    "RIPEMD160": ("^[a-fA-F0-9]{40}$", "RIPEMD-160"),
    "SHA1": ("^[a-fA-F0-9]{40}$", "SHA-1"),
    "SHA224": ("^[a-fA-F0-9]{56}$", "SHA-224"),
    "SHA256": ("^[a-fA-F0-9]{64}$", "SHA-256"),
    "SHA384": ("^[a-fA-F0-9]{96}$", "SHA-384"),
    "SHA512": ("^[a-fA-F0-9]{128}$", "SHA-512"),
    "SHA3224": ("^[a-fA-F0-9]{56}$", "SHA3-224"),
    "SHA3256": ("^[a-fA-F0-9]{64}$", "SHA3-256"),
    "SHA3384": ("^[a-fA-F0-9]{96}$", "SHA3-384"),
    "SHA3512": ("^[a-fA-F0-9]{128}$", "SHA3-512"),
    "SSDEEP": ("^[a-zA-Z0-9/+:.]{1,128}$", "ssdeep"),
    "WHIRLPOOL": ("^[a-fA-F0-9]{128}$", "WHIRLPOOL"),
}


class HashConstant(StringConstant):
    def __init__(self, value, type):
        key = type.upper().replace('-', '')
        if key in _HASH_REGEX:
            vocab_key = _HASH_REGEX[key][1]
            if not re.match(_HASH_REGEX[key][0], value):
                raise ValueError("'%s' is not a valid %s hash" % (value, vocab_key))
            self.value = value


class BinaryConstant(Constant):

    def __init__(self, value):
        try:
            base64.b64decode(value)
            self.value = value
        except (binascii.Error, TypeError):
            raise ValueError("must contain a base64 encoded string")

    def __str__(self):
        return "b'%s'" % self.value


class HexConstant(Constant):

    def __init__(self, value):
        if not re.match('^([a-fA-F0-9]{2})+$', value):
            raise ValueError("must contain an even number of hexadecimal characters")
        self.value = value

    def __str__(self):
        return "h'%s'" % self.value


class ListConstant(Constant):
    def __init__(self, values):
        self.value = values

    def __str__(self):
        return "(" + ", ".join([("%s" % x) for x in self.value]) + ")"


def make_constant(value):
    if isinstance(value, str):
        return StringConstant(value)
    elif isinstance(value, int):
        return IntegerConstant(value)
    elif isinstance(value, float):
        return FloatConstant(value)
    elif isinstance(value, list):
        return ListConstant(value)
    elif isinstance(value, bool):
        return BooleanConstant(value)
    else:
        raise ValueError("Unable to create a constant from %s" % value)
