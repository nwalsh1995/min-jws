from typing import NewType, Any, Union, Dict, List, TypedDict
from pydantic import Json, validator, BaseModel
from pydantic.dataclasses import dataclass


JSONType = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]  # Simple JSON representation.
JSON = Dict[str, JSONType]

# A data structure representing a digitally signed or MACed message
JWS = NewType("JWS", Any)

# JSON object containing the parameters describing the cryptographic operations and parameters employed.
JOSEHeader = NewType("JOSEHeader", JSON)

# The sequence of octets to be secured -- a.k.a. the message.  The payload can contain an arbitrary sequence of octets.
JWSPayload = NewType("JWSPayload", bytes)  # TODO: what type?

# Digital signature or MAC over the JWS Protected Header and the JWS Payload.
JWSSignature = NewType("JWSSignature", bytes)  # TODO: What type?

# A name/value pair that is member of the JOSE Header.
HeaderParameter = NewType("HeaderParameter", Any)

# JSON object that contains the Header Parameters that are integrity protected by the JWS Signature digital signature or MAC operation.
# For the JWS Compact Serialization, this comprises the entire JOSE Header.
# For the JWS JSON Serialization, this is one component of the JOSE Header.
JWSProtectedHeader = NewType("JWSProtectedHeader", JSON)

# JSON object that contains the Header Parameters that are not integrity protected.
# This can only be present when using the JWS JSON Serialization.
JWSUnprotectedHeader = NewType("JWSProtectedHeader", JSON)

# Base64 encoding using the URL- and filename-safe character set defined in Section 5 of RFC 4648 [RFC4648],
# with all trailing ’=’ characters omitted (as permitted by Section 3.2) and
# without the inclusion of any line breaks, whitespace, or other additional characters.
# Note that the base64url encoding of the empty octet sequence is the empty string.
Base64URL = NewType("Base64URL", bytes)

# The input to the digital signature or MAC computation.
# Its value is ASCII(BASE64URL(UTF8(JWS Protected Header)) || ’.’ || BASE64URL(JWS Payload)).
JWSSigningInput = NewType("JWSSigningInput", bytes)

# A representation of the JWS as a JSON object.
# Unlike the JWS Compact Serialization, the JWS JSON Serialization enables multiple digital signatures and/or MACs to be applied to the same content.
# This representation is neither optimized for compactness nor URL-safe.
JWSJSONSerialization = NewType("JWSJSONSerialization", JSONType)

# A JWS that provides no integrity protection.  Unsecured JWSs use the "alg" value "none".
UnsecuredJWS = NewType("UnsecuredJWS", JWS)

# A name in a namespace that enables names to be allocated in a manner such that they are highly unlikely to collide with other names.
CollisionResistantName = NewType("CollisionResistantName", str)

# A JSON string value, with the additional requirement that while arbitrary string values MAY be used,
# any value containing a ":" character MUST be a URI [RFC3986].
# StringOrURI values are compared as case-sensitive strings with no transformations or canonicalizations applied.
StringOrURI = NewType("StringOrURI", str)


class BaseGeneralJSONSerialiaztionSignatureMember(TypedDict):
    """7.2.1, this represent the base case, each sub-type must include signature."""
    signature: Base64URL


class GeneralJSONSerialiaztionSignatureMemberProtected(BaseGeneralJSONSerialiaztionSignatureMember):
    """7.2.1, represents when ProtectedSignature is sent but not Header."""
    protected: Base64URL


class GeneralJSONSerialiaztionSignatureMemberHeader(BaseGeneralJSONSerialiaztionSignatureMember):
    """7.2.1, represents when Header is sent but not ProtectedSignature."""
    header: JWSUnprotectedHeader


class GeneralJSONSerialiaztionSignatureMemberProtectedAndHeader(BaseGeneralJSONSerialiaztionSignatureMember):
    """7.2.1, represents when Header is sent but not ProtectedSignature."""
    protected: Base64URL
    header: JWSUnprotectedHeader


SignatureMembers = Union[GeneralJSONSerialiaztionSignatureMemberProtected,
                         GeneralJSONSerialiaztionSignatureMemberHeader,
                         GeneralJSONSerialiaztionSignatureMemberProtectedAndHeader]


class BaseGeneralJSONSerialization(TypedDict):
    payload: Base64URL
    signatures: List[SignatureMembers]


class ProtectedHeader(BaseModel):
    v: Json

    @validator("v")
    def validate_header(cls, v: Json) -> Json:
        """
        5.  Verify that the implementation understands and can process all
        fields that it is required to support, whether required by this
        specification, by the algorithm being used, or by the "crit"
        Header Parameter value, and that the values of those parameters
        are also understood and supported.
        """
        return v
        


@dataclass
class JWSCompactSerialization:
    protected_header: ProtectedHeader
    payload: JWSPayload
    signature: JWSSignature

    @validator('protected_header')
    def set_ts_now(cls, v):
        return v or datetime.now()

