from min_jws.utils import custom_urlsafe_b64encode, gen_signing_input
from min_jws.custom_types import AlgValidatorFn, JWS, JWSPayload, JOSEHeader

from typing import NewType


# JOSE Header must contain 'alg' key to be valid for produce.
ValidProduceJOSEHeader = NewType("ValidProduceJOSEHeader", JOSEHeader)


def validate_produce_jose_header(jose_header: JOSEHeader) -> ValidProduceJOSEHeader:
    """
    >>> validate_produce_jose_header({"alg": "HS256"})
    {'alg': 'HS256'}
    >>> validate_produce_jose_header({})
    Traceback (most recent call last):
        ...
    ValueError: alg is required in jose_header
    """
    if "alg" not in jose_header:
        raise ValueError("alg is required in jose_header")

    return ValidProduceJOSEHeader(jose_header)


def produce_compact(payload: JWSPayload, jose_header: JOSEHeader, alg_validator: AlgValidatorFn) -> JWS:
    return produce_compact_valid(payload, validate_produce_jose_header(jose_header), alg_validator)


def produce_compact_valid(payload: JWSPayload, jose_header: ValidProduceJOSEHeader, alg_validator: AlgValidatorFn) -> JWS:
    alg_fn = alg_validator(jose_header)

    signing_input = gen_signing_input(jose_header, payload)
    signature = custom_urlsafe_b64encode(alg_fn(signing_input))

    return JWS(b".".join((signing_input, signature)))
