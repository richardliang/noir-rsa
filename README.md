# noir-rsa

This repository contains an implementation of a RSA signature verify for the Noir language. Currently supports pkcs1v15 + sha256 and exponent is 65537.

The current implementation uses [Noir BigInt](https://github.com/richardliang/noir-bigint) library which adds `mul_mod` and `pow_mod` functions to shuklaayush's [Noir BigInt](https://github.com/shuklaayush/noir-bigint/).

This repo is under heavy development and should not be used in production. Currently `pow_mod` in BigInt runs into Noir compiler (v0.7.1) issues.

## Usage
Running tests
```
nargo test
```

## Ref
- [Noir BigInt](https://github.com/richardliang/noir-bigint)
- [Halo2 RSA](https://github.com/zkemail/halo2-rsa) 
- [Circom RSA](https://github.com/zkp-application/circom-rsa-verify)
- [Noir RSA Test Generation Scripts](https://github.com/SetProtocol/noir_rsa_scripts)
