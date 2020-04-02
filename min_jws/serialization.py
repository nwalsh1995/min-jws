from min_jws.custom_types import (
    JWSCompactSerialization, JWSProtectedHeader, JWSPayload, JWSSignature, JSON, JWSUnprotectedHeader,
    SignatureMembers, JWSSigningInput, JWS, JWSCompactSerialization
)
from typing import List, Any, Callable
from min_jws.utils import custom_dumps, custom_urlsafe_b64encode, custom_urlsafe_b64decode
from pydantic.dataclasses import dataclass


def parse_jws_compact(jws: bytes) -> JWSCompactSerialization:
    parts = jws.split(b".")
    if len(parts) != 3:
        raise ValueError("invalid compact jws")
    
    protected_header_str = custom_urlsafe_b64decode(part[0]).decode("utf-8")

    return JWSCompactSerialization(
        protected_header=ProtectedHeader(protected_header_str),
        payload=JWSPayload(parts[1]),
        signature=JWSSignature(parts[2]),
    )


def b64_utf8(value: JSON) -> bytes:
    """
    >>> b64_utf8({"typ": "JWT", "alg": "HS256"})  # Header
    b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    >>> b64_utf8({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})  # Payload
    b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    """
    return custom_urlsafe_b64encode(custom_dumps(value).encode("utf-8"))


def jws_payload_from_dict(payload: JSON) -> JWSPayload:
    return JWSPayload(custom_dumps(payload).encode("utf-8"))


def jws_signing_input(protected_header: JWSProtectedHeader, payload: JWSPayload) -> JWSSigningInput:
    """
    The input to the digital signature or MAC computation.

    Its value is ASCII(BASE64URL(UTF8(JWS Protected Header)) || ’.’ || BASE64URL(JWS Payload))

    >>> jws_signing_input(protected_header=JWSProtectedHeader({"typ": "JWT", "alg": "HS256"}), payload=jws_payload_from_dict({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}))
    b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    """
    return JWSSigningInput(
        b".".join(
            (
                b64_utf8(protected_header),
                custom_urlsafe_b64encode(payload),
            )
        )
    )


def jws_compact_serialization(protected_header: JWSProtectedHeader,
                              payload: JWSPayload,
                              signature: JWSSignature) -> JWSCompactSerialization:
    """
    In the JWS Compact Serialization, no JWS Unprotected Header is used. In this case, the JOSE Header and the JWS Protected Header are the same.
    """
    return JWSCompactSerialization(b".".join((
        b64_utf8(protected_header),
        custom_urlsafe_b64encode(payload),
        custom_urlsafe_b64encode(signature)
    )))


def jws_json_serialization(payload: JWSPayload, signatures: List[SignatureMembers]) -> JSON:
    """The case where JSONProtectedHeader is sent but unprotected header is not present."""
    return {
        "payload": custom_urlsafe_b64encode(payload),
        "signatures": signatures
    }


def flattened_jws_json_serialization(payload: JWSPayload,
                                     protected_header: JWSProtectedHeader,
                                     header: JWSUnprotectedHeader,
                                     signature: JWSSignature):
    return {
        "payload": payload,
        "protected": protected_header,
        "header": header,
        "signature": signature,
    }
