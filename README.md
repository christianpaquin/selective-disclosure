# Simple selective disclosure for JSON Web Tokens 

**NOTE**: this project is a work in progress

The [JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc7519) (JWT) offer a popular format to present claims (attributes) online (e.g., in OAuth and OpenID Connect). A trusted issuer can sign a JWT, creating a [JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), allowing anyone with the issuer's public key to verify the authenticity and integrity of the claims. By design, no one can modify the JWS without invalidating its signature. One consequence is that all the encoded claims must presented to a relying party, even if only a subset would satisfy its access policy.

In settings where users hold reusable long-lived tokens, it would be desirable to allow them to selectively disclose a subset of the claims encoded in a JWS, to meet a relying party's minimum access policy requirements. This _minimal disclosure_ aspect has long been explored in privacy-protecting identity systems, such as [U-Prove](https://www.microsoft.com/uprove) and [Idemix](https://github.com/IBM/idemix), and supported in more recent frameworks such as [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and [JSON Web Proofs](https://github.com/json-web-proofs/json-web-proofs). Although these systems support rich cryptographic mechanisms for advanced claim disclosures (e.g., issuance/presentation unlinkability and derived claims (aka predicate proofs)), simple easy-to-implement methods could be used to provide straightforward subset claim disclosure, allowing users to hide some of the encoded claims on-demand. As an example, a hashed-based approach has been adopted by the [ISO mobile Driver License](https://www.iso.org/standard/69084.html) (mDL) standard.

This project explores methods to provide selective claim disclosure for and within generic JWTs using conventional cryptographic techniques. This is done be specifying a new claim type encoding selectively-disclosable claims; users (holders) and verifiers (relying parties) supporting the feature can hide and verify said claims.

## Hash-based selective disclosure

This section specifies a simple hash-based selective disclosure mechanism for JWT.

### Overview

In addition to normal, always-disclosed claims, a set of selectively-disclosable claims can be encoded by the issuer into a `sdDigests` object in the JWT, containing the salted hash digests of the claims values. The corresponding pre-image data (the salts and claim values) are encoded in a `sdData` object in the JWS unprotected header. A verifier can validate the claim digests using the claim data; a user can hide some of these claims by deleting the corresponding `sdData` values, without affecting the JWS integrity. Since the hash digest of the (disclosed and hidden) claims are always visible to the verifier, a strong digest derivation function can be used to prevent offline brute-force attacks to recover the hidden claims. 

### Digest derivation function

Various salted digest derivation functions (DDF) offer different levels of brute-force resistance. The supported functions must take a salt (byte array) and a claim value (UTF8 encoding of string value (TODO: support other claim types)) and return a digest (byte array). Two DDF choices are currently available (TODO: specify/test more, e.g., hmac (as proposed in this [JWP PR](https://github.com/json-web-proofs/json-web-proofs/pull/48)), bcrypt, argon2):

#### PBKDF2-HMAC-SHA256-310000

This function uses the [PBKDF2](https://datatracker.ietf.org/doc/html/rfc2898) key derivation function on the salt and claim value, instantiated with HMAC-SHA256 with a 310,000 iteration count, returning a 32 byte digest, as recommended by the [OWASP password storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

#### SHA256

This function returns the SHA256 digest of the salt concatenated with the claim value.

### JWT issuance

During issuance, the issuer selects the digest derivation function `ddf` and adds `"sdDDF": ddf` to the JWS protected header. The issuer then creates empty `sdDigests` and `sdData` objects. For each selectively-disclosable claim (with name `n` and value `v`) (TODO: currently, only string values are considered; specify how to encode claims of any type), the issuer

1. picks a cryptographically-random 8-byte salt `s`,
2. calculates the hash digests `d = ddf(s,v)` (see above for details),
4. encodes the digest to base64url,
5. creates a new property in the `sdDigests` object with name `n` and value matching the resulting base64url digest, and
6. creates a new property in the `sdData` object with name `n` and value `{"s": base64url(s), "v": v}` (an object encoding the base64url encoding of the salt and the claim value)

The issuer adds the `"sdData": sdData` object to the JWS unprotected headers, and add `"sdDigests": sdDigests` to the JWT payload.

### JWT presentation

Presenting the JWS as received by the issuer will disclose all the claims. To hide some of the selectively-disclosable claims, the user can delete the corresponding values from the JWS's `sdData` object in the JWS unprotected header.

### JWT validation

The relying party validates the JWS as it typically does. If the `sdData` object is specified in the JWS unprotected header, and if the `sdDigests` object is specified in the JWT (in the JWS payload), the verifier then, for each claim `n` with digest `d` (from the `sdDigests` object), salt `s` and value `v` (from the `sdData` object), verifies that `d = base64url.encode(ddf(base64url.decode(s),v))` (using the digest derivation function specified in the JWS protected header's `sdDDF` property).

### Example

This example was generated by running the `./hashSdJwt.js` script. To run the script:
* Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system (the latest Long-Term Support (LTS) version is recommended for both).
* Install the project: `npm install`
* Run the script: `node hashSdJwt.js`


JWT to sign: 

```json
{
  "iss": "https://example.org",
  "nbf": 1648226603.76,
  "abc": 1,
  "foo": "bar",
  "over21": true
}
```

Selectively-disclosable claims:

```json
{
  "given_name": "Jason",
  "middle_name": "Webb",
  "family_name": "Token",
  "https://example.org/custom": "custom value"
}
```

Digest derivation function: PBKDF2-HMAC-SHA256-310000

JWT with `sdDigests`:

```json
{
  "iss": "https://example.org",
  "nbf": 1648226603.76,
  "abc": 1,
  "foo": "bar",
  "over21": true,
  "sdDigests": {
    "given_name": "7nZ0_GSYDGwM-CX2yGl9ERZSZInNEofV6g9BkfBOqa4",
    "middle_name": "b1dgUQ4WIcmkWWNU_FBp3VAbWhObBipfG5YmZzsWM-U",
    "family_name": "18Jzz4vAL6BxVgWhxwi-o0W990_iazoR5bLj3C1arcs",
    "https://example.org/custom": "A8WkTPsRdxzl77MHgA-4WoLRCNvUpE7lqqUIUE73Oz8"
  }
}
```

JWS header:

```json
{
  "alg": "ES256",
  "sdDDF": "PBKDF2-HMAC-SHA256-310000"
}
```

JWS unprotected header:

```json
{
  "sdData": {
    "given_name": {
      "s": "GngdjaPuE_I",
      "v": "Jason"
    },
    "middle_name": {
      "s": "CDbzUH2BDnA",
      "v": "Webb"
    },
    "family_name": {
      "s": "8bQJNYrs4_M",
      "v": "Token"
    },
    "https://example.org/custom": {
      "s": "erZd7K12pOg",
      "v": "custom value"
    }
  }
}
```


JWS: 

```json
{
  "signature": "2TMsBQ3EepeOmqy5-JwNGrrdbsps_GOieyDLo6HDzQNIjrmyI1HUeq-wfwSNDwXH4WvVhKlRlEEEzTMqqygicA",
  "payload": "eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwibmJmIjoxNjQ4MjI2NjAzLjc2LCJhYmMiOjEsImZvbyI6ImJhciIsIm92ZXIyMSI6dHJ1ZSwic2REaWdlc3RzIjp7ImdpdmVuX25hbWUiOiI3blowX0dTWURHd00tQ1gyeUdsOUVSWlNaSW5ORW9mVjZnOUJrZkJPcWE0IiwibWlkZGxlX25hbWUiOiJiMWRnVVE0V0ljbWtXV05VX0ZCcDNWQWJXaE9iQmlwZkc1WW1aenNXTS1VIiwiZmFtaWx5X25hbWUiOiIxOEp6ejR2QUw2QnhWZ1doeHdpLW8wVzk5MF9pYXpvUjViTGozQzFhcmNzIiwiaHR0cHM6Ly9leGFtcGxlLm9yZy9jdXN0b20iOiJBOFdrVFBzUmR4emw3N01IZ0EtNFdvTFJDTnZVcEU3bHFxVUlVRTczT3o4In19",
  "header": {
    "sdData": {
      "given_name": {
        "s": "GngdjaPuE_I",
        "v": "Jason"
      },
      "middle_name": {
        "s": "CDbzUH2BDnA",
        "v": "Webb"
      },
      "family_name": {
        "s": "8bQJNYrs4_M",
        "v": "Token"
      },
      "https://example.org/custom": {
        "s": "erZd7K12pOg",
        "v": "custom value"
      }
    }
  },
  "protected": "eyJhbGciOiJFUzI1NiIsInNkRERGIjoiUEJLREYyLUhNQUMtU0hBMjU2LTMxMDAwMCJ9"
}
```

To hide the "middle_name" and "family_name" claims, the user removes the corresponding properties from the unprotected header's `sdData` object:

```json
{
  "signature": "2TMsBQ3EepeOmqy5-JwNGrrdbsps_GOieyDLo6HDzQNIjrmyI1HUeq-wfwSNDwXH4WvVhKlRlEEEzTMqqygicA",
  "payload": "eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwibmJmIjoxNjQ4MjI2NjAzLjc2LCJhYmMiOjEsImZvbyI6ImJhciIsIm92ZXIyMSI6dHJ1ZSwic2REaWdlc3RzIjp7ImdpdmVuX25hbWUiOiI3blowX0dTWURHd00tQ1gyeUdsOUVSWlNaSW5ORW9mVjZnOUJrZkJPcWE0IiwibWlkZGxlX25hbWUiOiJiMWRnVVE0V0ljbWtXV05VX0ZCcDNWQWJXaE9iQmlwZkc1WW1aenNXTS1VIiwiZmFtaWx5X25hbWUiOiIxOEp6ejR2QUw2QnhWZ1doeHdpLW8wVzk5MF9pYXpvUjViTGozQzFhcmNzIiwiaHR0cHM6Ly9leGFtcGxlLm9yZy9jdXN0b20iOiJBOFdrVFBzUmR4emw3N01IZ0EtNFdvTFJDTnZVcEU3bHFxVUlVRTczT3o4In19",
  "header": {
    "sdData": {
      "given_name": {
        "s": "GngdjaPuE_I",
        "v": "Jason"
      },
      "https://example.org/custom": {
        "s": "erZd7K12pOg",
        "v": "custom value"
      }
    }
  },
  "protected": "eyJhbGciOiJFUzI1NiIsInNkRERGIjoiUEJLREYyLUhNQUMtU0hBMjU2LTMxMDAwMCJ9"
}
```



### Notes

* Digests could be truncated to provide more compact JWS. It's preferable to truncate a more secure hash function's output rather than using a smaller, less secure hash function. Alternatively, an extendable-output function could be used.
* The technique could be used for compact and normal (non-flattened) JWS, although the `sdData` would need to be encoded separately for the compact case (since compact JWS don't use unprotected headers). The [Claim QR](https://github.com/microsoft/claimqr) project, for example, creates a fourth "appendix" part to the JWS.
* The mechanism could also be used for [CBOR Web Tokens](https://www.rfc-editor.org/rfc/rfc8392) (CWT).
* One alternative option is to encode the `sdData` outside of the JWS, and provide it along with the JWS to the verifier; this would however require application-specific integration. Keeping the data self-contained is beneficial, especially for bearer tokens.
