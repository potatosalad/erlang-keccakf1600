# Changelog

## 2.0.0 (2016-02-05)

* Enhancements
  * Rewrite as NIF with timeslice reductions (roughly 10x faster).

* Breaking Changes
  * Previous API has been simplified to the following (using `sha3_512` as an example):
    * `Out = keccakf1600:hash(sha3_512, <<"test">>)`
    * `State0 = keccakf1600:init(sha3_512)`
    * `State1 = keccakf1600:update(State0, <<"test">>)`
    * `Out = keccakf1600:final(State1)`
  * The `shake128` and `shake256` algorithms are very similar, but require an output length (using `shake256` and `64` output length as an example):
    * `Out = keccakf1600:hash(shake256, <<"test">>, 64)`
    * `State0 = keccakf1600:init(shake256)`
    * `State1 = keccakf1600:update(State0, <<"test">>)`
    * `Out = keccakf1600:final(State1, 64)`

## 1.0.2 (2016-02-04)

* Fixes
  * Minor rebar configuration fix.

## 1.0.1 (2016-02-04)

* Fixes
  * Minor rebar configuration fix.

## 1.0.0 (2016-02-04)

* Enhancements
  * Streaming support
    * `keccakf1600_sha3_224:init/0`, `keccakf1600_sha3_224:update/2`, `keccakf1600_sha3_224:final/1`
    * `keccakf1600_sha3_256:init/0`, `keccakf1600_sha3_256:update/2`, `keccakf1600_sha3_256:final/1`
    * `keccakf1600_sha3_384:init/0`, `keccakf1600_sha3_384:update/2`, `keccakf1600_sha3_384:final/1`
    * `keccakf1600_sha3_512:init/0`, `keccakf1600_sha3_512:update/2`, `keccakf1600_sha3_512:final/1`
    * `keccakf1600_shake128:init/0`, `keccakf1600_shake128:update/2`, `keccakf1600_shake128:final/2`
    * `keccakf1600_shake256:init/0`, `keccakf1600_shake256:update/2`, `keccakf1600_shake256:final/2`

## 0.0.1 (2016-01-20)

* Initial Release

* Publish to [hex.pm](https://hex.pm/packages/keccakf1600).

* Library Support
  * `keccakf1600_fip202:shake128/2`
  * `keccakf1600_fip202:shake256/2`
  * `keccakf1600_fip202:sha3_224/1`
  * `keccakf1600_fip202:sha3_256/1`
  * `keccakf1600_fip202:sha3_384/1`
  * `keccakf1600_fip202:sha3_512/1`

* Basic Tests based on FIPS202 test vectors
