from min_jws.utils import custom_urlsafe_b64encode, b64_utf8
from min_jws.custom_types import AlgValidatorFn, JWS, JWSPayload, JOSEHeader


def produce_compact(payload: JWSPayload, jose_header: JOSEHeader, alg_validator: AlgValidatorFn) -> JWS:
    if "alg" not in jose_header:
        raise ValueError("alg is required in jose_header")

    encoded_payload = b64_utf8(payload)
    encoded_header = b64_utf8(jose_header)
    alg_fn = alg_validator(jose_header)

    signature = custom_urlsafe_b64encode(alg_fn(b".".join((encoded_header, encoded_payload))))

    return b".".join((encoded_header, encoded_payload, signature))
