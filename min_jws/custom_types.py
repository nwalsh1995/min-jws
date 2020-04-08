from typing import Any, Union, Dict, List, NewType, Callable


JSONType = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]  # Simple JSON representation.
JSON = Dict[str, JSONType]
JWSPayload = NewType("JWSPayload", JSON)
JWSPayloadBytes = NewType("JWSPayloadBytes", bytes)
JOSEHeader = NewType("JOSEHeader", JSON)
JWS = NewType("JWS", bytes)
JWSSigningInput = NewType("JWSSigningInput", bytes)
JWSSignature = NewType("JWSSignature", bytes)
AlgComputeFn = Callable[[JWSSigningInput], JWSSignature]
AlgValidatorFn = Callable[[JOSEHeader], AlgComputeFn]
JOSEValidatorFn = Callable[[JOSEHeader], AlgComputeFn]
