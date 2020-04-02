from typing import Callable
from min_jws.validator.compact_validator import validate_compact
from min_jws.validator.jose_validator import validate_jose_header, JOSEValidatorFn
import hmac
import hashlib
import functools


def alg_validate(jose_header) -> Callable[[bytes], bytes]:
    alg = jose_header["alg"]
    # hardcoding key for now
    key = b'\x03#5K+\x0f\xa5\xbc\x83~\x06ew{\xa6\x8fZ\xb3(\xe6\xf0T\xc9(\xa9\x0f\x84\xb2\xd2P.\xbf\xd3\xfbZ\x92\xd2\x06G\xef\x96\x8a\xb4\xc3wb="=.!r\x05.O\x08\xc0\xcd\x9a\xf5g\xd0\x80\xa3'

    if alg != "HS256":
        raise ValueError(f"{alg} not supported")

    return functools.partial(hmac.digest, key=key, digest=hashlib.sha256)





jose_validate_fn: JOSEValidatorFn = functools.partial(validate_jose_header, alg_validator=alg_validate, crit_validator=lambda *args, **kwargs: None)

validate_compact(b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", jose_validate_fn)
