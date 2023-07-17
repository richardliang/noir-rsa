# noir-rsa

This repository contains an implementation of a RSA signature verify for the Noir language. Currently supports pkcs1v15 + sha256 and exponent is 65537.

The current implementation uses shuklaayush's [Noir BigInt](https://github.com/richardliang/noir-bigint) with additional `mul_mod` and `pow_mod` functions.

This repo is under heavy development and should not be used in production. TODO: currently pow_mod in BigInt runs into Noir compiler issues as of Noir 0.7.1 and 0.8.0 version and does not work for the full 65537 exponentiation.

## Usage
Running tests
```
nargo test
```

## Ref
- [Noir BigInt](https://github.com/richardliang/noir-bigint)
- [Halo2 RSA](https://github.com/zkemail/halo2-rsa) 
- [Circom RSA](https://github.com/zkp-application/circom-rsa-verify) 