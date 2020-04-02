# min-jws
an attempt at minimally fulfilling the requirements of RFC 7515 while maintaining extensibility for client programs.

# requirements
the following functionality must be passed in from clients using this library:

	* the full jws as `bytes`
	* a callable that validates the JOSE header according to your requirements
		* should handle the `alg` header
		* should handle the `crit` header
		* should handle any extra logic you want to do on the header


# helpers
there exist some functions which can be partially implemented in order for ease-of-use. for instance, `min_jws.validator.jose_validator.validate_jose_header` contains a generic structure for validating the JOSE header. it allows you to pass in callables to specify how to handle `alg` header, how to handle `crit` header, and how to handle any custom logic on headers. `validate_jose_header` is a function that relies on other callables, so you can partially implement it and then pass it around later.

# typing
this package was developed with types in mind. in order to correctly integrate and see the format of callables during development, it is encouraged to type-check.

# example

## compact jws

```python
from typing import Callable
from min_jws.validator.compact_validator import validate_compact
from min_jws.validator.jose_validator import validate_jose_header, JOSEValidatorFn
import hmac
import hashlib
import functools


# this is where we define which algorithms our app can use
# min-jws expects a callable which can generate the jws signature
# in this example, we only support HS256
def alg_validate(jose_header) -> Callable[[bytes], bytes]:
    alg = jose_header["alg"]  # guaranteed to exist by this point

    if alg != "HS256":
        raise ValueError(f"{alg} not supported")

    # hardcoding key for now, you can determine how to retrieve your key based on `jose_header` if necessary
    key = b'\x03#5K+\x0f\xa5\xbc\x83~\x06ew{\xa6\x8fZ\xb3(\xe6\xf0T\xc9(\xa9\x0f\x84\xb2\xd2P.\
xbf\xd3\xfbZ\x92\xd2\x06G\xef\x96\x8a\xb4\xc3wb="=.!r\x05.O\x08\xc0\xcd\x9a\xf5g\xd0\x80\xa3'

	# return the callable that can generate a signature for this alg
    return lambda msg: hmac.digest(key=key, msg=msg, digest=hashlib.sha256)


# bind our validator functions to `validate_jose_header`
jose_validate_fn: JOSEValidatorFn = functools.partial(validate_jose_header, alg_validator=alg_validate, crit_validator=lambda *args, **kwargs: None)

# finally pass our `jose_validate_fn` to `validate_compact` and send the jws as bytes
validate_compact(b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", jose_validate_fn)
# no exception means the signature was verified
```
