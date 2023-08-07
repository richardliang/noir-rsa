# noir-rsa

This library contains an implementation of a RSA signature verify for the Noir language. RSA is one of the most widely used digital signature schemes in Web2 applications, such as DKIM email verification, TLS, message encryption etc

The repo contains 2 crates:
- rsa-biguint - Fork of shuklaayush's [Noir BigInt](https://github.com/shuklaayush/noir-bigint/) v0.1.0 with additional functionality
- rsa - RSA signature verification library

### RSA BigUint
Fork of v0.1.0 of [Noir BigInt](https://github.com/shuklaayush/noir-bigint) with the following updates:
- Updated constants for a max 2048 bit RSA. The BigInt lib only supports 5 limbs
- Added mulmod and powmod functions
- Use unconstrained division for powmod

### RSA
Currently, Noir RSA supports pkcs1v15, sha256, max RSA modulus of 2048 bits and a max exponent value of 17 bits. Typical RSA modulus sizes are 512, 1024 and 2048 bits. And typically, 65537 is used as the public exponent (which is <2^17). 

This repo is under heavy development and should not be used in production.

## Usage
Running tests
```
nargo test --show-output
```

## Ref
- [Noir BigInt](https://github.com/shuklaayush/noir-bigint/)
- [Halo2 RSA](https://github.com/zkemail/halo2-rsa) 
- [Circom RSA](https://github.com/zkp-application/circom-rsa-verify)
- [Noir RSA Test Generation Scripts](https://github.com/SetProtocol/noir_rsa_scripts)