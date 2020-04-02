import json
from min_jws.custom_types import JSON
from min_jws.utils import custom_urlsafe_b64encode, custom_urlsafe_b64decode, custom_dumps
from min_jws.validator.jose_validator import JOSEValidatorFn

def b64_utf8(value: JSON) -> bytes:
    """
    >>> b64_utf8({"typ": "JWT", "alg": "HS256"})  # Header
    b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    >>> b64_utf8({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})  # Payl
oad
    b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0c
nVlfQ'
    """
    return custom_urlsafe_b64encode(custom_dumps(value).encode("utf-8"))



def generate_signature(alg_fn, protected_header: JSON, payload: bytes) -> bytes:
    return alg_fn(msg=b".".join((b64_utf8(protected_header), custom_urlsafe_b64encode(payload))))
    


def validate_compact(jws: bytes, validate_jose_header: JOSEValidatorFn):
    parts = jws.split(b".")
    if len(parts) != 3:
        raise ValueError("invalid compact jws")

    try:
        # todo: line breaks?
        # 5.2.2, 5.2.6, 5.2.7
        protected_header_bytes, payload_bytes, signature_bytes = (custom_urlsafe_b64decode(p) for p in parts)
    except Exception:
        raise ValueError("bad") 
    
    try:
        # 5.2.3
        protected_header = json.loads(protected_header_bytes)
    except Exception:
        raise ValueError("bad")

    # 5.2.4
    jose_header = protected_header
    
    # 5.2.5
    alg_fn = validate_jose_header(jose_header)

    # 5.2.8
    signature = custom_urlsafe_b64encode(generate_signature(alg_fn, protected_header, payload_bytes))
    if parts[2] != signature:
        raise ValueError("signatures dont match")
