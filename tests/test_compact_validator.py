from min_jws.validator.compact_validator import validate_compact
from min_jws.validator.jose_validator import validate_jose_header
from min_jws.producer.compact_producer import produce_compact
from min_jws.custom_types import JOSEValidatorFn, JOSEHeader, AlgComputeFn, JWSSignature, JWSPayload
import hmac
import functools

EXPECTED = b"""eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"""  # noqa: E501
# hardcoding key for now
KEY = b"""\x03#5K+\x0f\xa5\xbc\x83~\x06ew{\xa6\x8fZ\xb3(\xe6\xf0T\xc9(\xa9\x0f\x84\xb2\xd2P.\xbf\xd3\xfbZ\x92\xd2\x06G\xef\x96\x8a\xb4\xc3wb="=.!r\x05.O\x08\xc0\xcd\x9a\xf5g\xd0\x80\xa3"""  # noqa: E501


def alg_validate(jose_header: JOSEHeader) -> AlgComputeFn:
    alg = jose_header["alg"]

    if alg != "HS256":
        raise ValueError(f"{alg} not supported")

    return lambda msg: JWSSignature(hmac.digest(key=KEY, msg=msg, digest="sha256"))


def test_produce_compact() -> None:
    jws = produce_compact(
        payload=JWSPayload({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}),
        jose_header=JOSEHeader({"typ": "JWT", "alg": "HS256"}),
        alg_validator=alg_validate,
    )
    assert jws == EXPECTED


def test_validate_compact() -> None:
    jose_validate_fn: JOSEValidatorFn = functools.partial(validate_jose_header, alg_validator=alg_validate, crit_validator=lambda *args, **kwargs: None)

    validate_compact(
        EXPECTED, jose_validate_fn,
    )
