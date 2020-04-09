import json
from min_jws.custom_types import JOSEValidatorFn, JWSPayloadBytes
from min_jws.utils import custom_urlsafe_b64encode, custom_urlsafe_b64decode, b64_utf8, gen_signing_input_bytes


def validate_compact(jws: bytes, validate_jose_header: JOSEValidatorFn) -> JWSPayloadBytes:
    parts = jws.split(b".")
    if len(parts) != 3:
        raise ValueError("invalid compact jws")

    encoded_payload_bytes = parts[1]
    try:
        # todo: line breaks?
        # 5.2.2, 5.2.6, 5.2.7
        protected_header_bytes = custom_urlsafe_b64decode(parts[0])
    except Exception:
        raise ValueError("cannot b64decode")

    try:
        # 5.2.3
        protected_header = json.loads(protected_header_bytes)
    except Exception:
        raise ValueError("cannot load protected header as JSON")

    # 5.2.4
    jose_header = protected_header

    # 5.2.5
    alg_fn = validate_jose_header(jose_header)
    signing_input = gen_signing_input_bytes(header=b64_utf8(jose_header), payload=encoded_payload_bytes)

    # 5.2.8
    signature = custom_urlsafe_b64encode(alg_fn(signing_input))
    if parts[2] != signature:
        raise ValueError("signatures dont match")

    return JWSPayloadBytes(custom_urlsafe_b64decode(encoded_payload_bytes))
