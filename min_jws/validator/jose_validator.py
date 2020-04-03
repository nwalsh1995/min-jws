from min_jws.custom_types import JSON, JOSEHeader, AlgValidatorFn
from typing import Callable, NewType, Optional

JWSPayload = NewType("JWSPayload", str)
CritValidateFn = Callable[[JOSEHeader], None]
CustomValidatorFn = Callable[[JOSEHeader], None]


def validate_jose_header(jose_header: JOSEHeader, alg_validator: AlgValidatorFn, crit_validator: CritValidateFn, custom_validator: Optional[CustomValidatorFn] = None) -> Callable:
    if "alg" not in jose_header:
        raise ValueError("alg is required")

    if "crit" in jose_header:
       crit_validator(jose_header) 

    if custom_validator is not None:
        custom_validator(jose_header)

    return alg_validator(jose_header)

