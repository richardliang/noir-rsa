# noir-rsa

[![CI][ci-shield]][ci-url]
[![MIT License][license-shield]][license-url]

This library contains an implementation of a RSA signature verify for the Noir language. RSA is one of the most widely used digital signature schemes in Web2 applications, such as DKIM email verification, TLS, message encryption etc

The repo contains 2 crates and 1 example circuit:
- rsa-biguint - Fork of shuklaayush's [Noir BigInt](https://github.com/shuklaayush/noir-bigint/) v0.1.0 with additional functionality
- rsa - RSA signature verification library
- dkim - DKIM email verification circuit

### RSA BigUint
Fork of v0.1.0 of [Noir BigInt](https://github.com/shuklaayush/noir-bigint) with the following updates:
- Updated constants for a max 2048 bit RSA. The BigInt lib only supports 5 limbs
- Added mulmod and powmod functions
- Use unconstrained division for powmod

### RSA
Currently, Noir RSA supports pkcs1v15, sha256, max RSA modulus of 2048 bits and a max exponent value of 17 bits. Typical RSA modulus sizes are 512, 1024 and 2048 bits. And typically, 65537 is used as the public exponent (which is <2^17). 

### DKIM Verification
Verifies a email DKIM signature which signs an email header. The email header comprises of fields such as `From`, `To`, `Subject` and `bh` (hash of the email body encoded in base64). The circuit does the following:
1. Decodes the base64 body hash
2. Hash email body (in bytes) using sha256
3. Compares the hash of the email body with the decoded base64 body hash
4. Hash email header (in bytes) using sha256
5. Verifies the RSA signature matches the public key and the hash of the email header

This repo is under heavy development and should not be used in production.

## Usage
Running tests

For the RSA crate:
```
cd crates/rsa
nargo test --show-output
```

For the RSA biguint crate:
```
cd crates/rsa-biguint
nargo test --show-output
```

For the DKIM example
```
cd examples/dkim
nargo test --show-output

nargo compile
// BUG: below doesn't work due to compiler bug
nargo prove
```

## Ref
- [Noir BigInt](https://github.com/shuklaayush/noir-bigint/)
- [Halo2 RSA](https://github.com/zkemail/halo2-rsa) 
- [Circom RSA](https://github.com/zkp-application/circom-rsa-verify)
- [Noir RSA Test Generation Scripts](https://github.com/SetProtocol/noir_rsa_scripts)

[ci-shield]: https://img.shields.io/github/actions/workflow/status/SetProtocol/noir-rsa/test.yaml?branch=main&label=tests
[ci-url]: https://github.com/SetProtocol/noir-rsa/actions/workflows/test.yaml

[license-shield]: https://img.shields.io/badge/License-MIT-green.svg
[license-url]: https://github.com/SetProtocol/noir-rsa/blob/main/LICENSE