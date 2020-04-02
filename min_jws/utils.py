import base64
import json
from min_jws.custom_types import JSON


def custom_urlsafe_b64encode(value: bytes) -> bytes:
    """Remove padding to be same as RFC 7515."""
    return base64.urlsafe_b64encode(value).strip(b"=")


def custom_urlsafe_b64decode(value: bytes) -> bytes:
    """We add padding onto the value so that if padding was removed we still parse correctly."""
    return base64.urlsafe_b64decode(value + b"===")


def custom_dumps(value: JSON) -> str:
    """Returns the JSON value as a string with the proper separators matching the one in RFC."""
    return json.dumps(value, ensure_ascii=False, separators=(",\r\n ", ":"))
