# Changelog

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
