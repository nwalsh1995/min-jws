import base64
import json
from min_jws.custom_types import JSON, JOSEHeader, JWSPayload, JWSSigningInput


def b64_utf8(value: JSON) -> bytes:
    """
    >>> b64_utf8({"typ": "JWT", "alg": "HS256"})  # Header
    b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    >>> b64_utf8({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})  # Payload
    b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    """
    return custom_urlsafe_b64encode(custom_dumps(value).encode("utf-8"))


def custom_urlsafe_b64encode(value: bytes) -> bytes:
    """Remove padding to be same as RFC 7515."""
    return base64.urlsafe_b64encode(value).strip(b"=")


def gen_signing_input(header: JOSEHeader, payload: JWSPayload) -> JWSSigningInput:
    """
    >>> gen_signing_input(header={"typ": "JWT", "alg": "HS256"}, payload={"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})  # Header
    b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    """
    return gen_signing_input_bytes(header=b64_utf8(header), payload=b64_utf8(payload))


def gen_signing_input_bytes(header: bytes, payload: bytes) -> JWSSigningInput:
    """
    >>> gen_signing_input_bytes(header=b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
    ... payload=b"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")  # Header
    b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    """
    return JWSSigningInput(b".".join((header, payload)))


def custom_urlsafe_b64decode(value: bytes) -> bytes:
    """We add padding onto the value so that if padding was removed we still parse correctly."""
    return base64.urlsafe_b64decode(value + b"===")


def custom_dumps(value: JSON) -> str:
    """Returns the JSON value as a string with the proper separators matching the one in RFC."""
    return json.dumps(value, ensure_ascii=False, separators=(",\r\n ", ":"))
