from min_jws.utils import custom_urlsafe_b64encode, gen_signing_input
from min_jws.custom_types import AlgValidatorFn, JWS, JWSPayload, JOSEHeader


def produce_compact(payload: JWSPayload, jose_header: JOSEHeader, alg_validator: AlgValidatorFn) -> JWS:
    if "alg" not in jose_header:
        raise ValueError("alg is required in jose_header")

    alg_fn = alg_validator(jose_header)

    signing_input = gen_signing_input(jose_header, payload)
    signature = custom_urlsafe_b64encode(alg_fn(signing_input))

    return JWS(b".".join((signing_input, signature)))
