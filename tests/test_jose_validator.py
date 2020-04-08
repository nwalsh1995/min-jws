from min_jws.validator.jose_validator import validate_jose_header
from min_jws.custom_types import JOSEHeader, AlgComputeFn, JWSSignature
import hmac
import hashlib
from unittest.mock import Mock

import pytest

EXPECTED = b"""eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"""  # noqa: E501
# hardcoding key for now
KEY = b"""\x03#5K+\x0f\xa5\xbc\x83~\x06ew{\xa6\x8fZ\xb3(\xe6\xf0T\xc9(\xa9\x0f\x84\xb2\xd2P.\xbf\xd3\xfbZ\x92\xd2\x06G\xef\x96\x8a\xb4\xc3wb="=.!r\x05.O\x08\xc0\xcd\x9a\xf5g\xd0\x80\xa3"""  # noqa: E501


def alg_validate(jose_header: JOSEHeader) -> AlgComputeFn:
    alg = jose_header["alg"]

    if alg != "HS256":
        raise ValueError(f"{alg} not supported")

    return lambda msg: JWSSignature(hmac.new(key=KEY, msg=msg, digestmod=hashlib.sha256).digest())


def test_validate_jose_header_invalid():
    # no alg
    with pytest.raises(ValueError):
        validate_jose_header(JOSEHeader({}), alg_validate, lambda *args, **kwargs: None)

    # crit specified
    jose_header = JOSEHeader({"alg": "HS256", "crit": "abc"})
    mock_crit_handler = Mock()
    validate_jose_header(jose_header, alg_validate, mock_crit_handler)
    mock_crit_handler.assert_called_once_with(jose_header)

    # custom handler
    custom_validator = Mock()
    validate_jose_header(jose_header, alg_validate, alg_validate, custom_validator=custom_validator)
    custom_validator.assert_called_once_with(jose_header)
