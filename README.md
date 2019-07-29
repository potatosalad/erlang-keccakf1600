# Keccak-f[1600] NIF (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, SPONGERNG)

[![Build Status](https://travis-ci.org/potatosalad/erlang-keccakf1600.svg?branch=master)](https://travis-ci.org/potatosalad/erlang-keccakf1600) [![Hex.pm](https://img.shields.io/hexpm/v/keccakf1600.svg)](https://hex.pm/packages/keccakf1600)

[Keccak-f[1600]](http://keccak.noekeon.org/) NIF with timeslice reductions for Erlang and Elixir.

The timeslice reductions allow the NIF to perform operations on very large inputs without blocking the scheduler or requiring the Erlang VM to support dirty schedulers.  See the [bitwise](https://github.com/vinoski/bitwise) project from which the strategy was derived.

Tested against the [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) test vectors.

## Installation

Add `keccakf1600` to your project's dependencies in `mix.exs`

```elixir
defp deps do
  [
    {:keccakf1600, "~> 3.0.0"}
  ]
end
```

Add `keccakf1600` to your project's dependencies in your `Makefile` for [`erlang.mk`](https://github.com/ninenines/erlang.mk) or the following to your `rebar.config`

```erlang
{deps, [
  {keccakf1600, ".*", {git, "git://github.com/potatosalad/erlang-keccakf1600.git", {branch, "master"}}}
]}.
```

## Usage

This library follows usage semantics from Erlang's own [`crypto`](http://erlang.org/doc/man/crypto.html) library, with the exception of the SHAKE128, SHAKE256, and SPONGERNG algorithms as described below.

##### SPONGERNG

#### `keccakf1600_spongerng:init_from_buffer/2`

This function allows you to specify an initial seed buffer and whether the PRNG will be deterministic or not.

```erlang
%% Deterministic
keccakf1600_spongerng:init_from_buffer(<<>>, true).
% {spongerng, #Ref<0.0.0.1>}
%% Non-deterministic
keccakf1600_spongerng:init_from_buffer(<<>>, false).
% {spongerng, #Ref<0.0.0.2>}
```

#### `keccakf1600_spongerng:init_from_file/3`

This function allows you specify an initial seed file up to the given length and whether the PRNG will be deterministic or not.

```erlang
%% Deterministic
keccakf1600_spongerng:init_from_file("seed.txt", 16, true).
% {spongerng, #Ref<0.0.0.3>}
%% Non-deterministic
keccakf1600_spongerng:init_from_file("seed.txt", 16, false).
% {spongerng, #Ref<0.0.0.4>}
```

#### `keccakf1600_spongerng:init_from_dev_urandom/0`

This function reads an initial seed from `/dev/urandom` and is only allowed to be non-deterministic.

```erlang
%% Non-deterministic
keccakf1600_spongerng:init_from_dev_urandom().
% {spongerng, #Ref<0.0.0.5>}
```

#### `keccakf1600_spongerng:next/2`

This function returns the next length of bytes from the sponge and returns the new sponge state.

```erlang
Sponge0 = keccakf1600_spongerng:init_from_buffer(<<>>, true),
{Sponge1, Output} = keccakf1600_spongerng:next(Sponge0, 8).
% {{spongerng, #Ref<0.0.0.6>}, <<99,190,253,62,125,162,80,150>>}
```

#### `keccakf1600_spongerng:stir/2`

This function modifies the sponge state (stirs the pot) with the given input.

```erlang
Sponge0 = keccakf1600_spongerng:init_from_buffer(<<>>, true),
Sponge1 = keccakf1600_spongerng:stir(Sponge0, <<"test">>),
{Sponge2, Output} = keccakf1600_spongerng:next(Sponge1, 8).
% {{spongerng, #Ref<0.0.0.7>}, <<168,214,5,0,60,110,186,33>>}
```

### SHA-3

#### `keccakf1600_sha3:hash/2`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)

```erlang
keccakf1600_sha3:hash(sha3_224, <<"test">>).
% <<55,151,191,10,251,191,202,74,123,187,167,96,42,43,85,39,70,135,101,23,167,249,183,206,45,176,174,123>>

keccakf1600_sha3:hash(sha3_256, <<"test">>).
% <<54,240,40,88,11,176,44,200,39,42,154,2,15,66,0,227,70,226,118,174,102,78,69,238,128,116,85,116,226,245,171,128>>

keccakf1600_sha3:hash(sha3_384, <<"test">>).
% <<229,22,218,187,35,182,227,0,38,134,53,67,40,39,128,163,174,13,204,240,85,81,207,2,149,23,141,127,240,241,180,30,236,185,219,63,242,25,0,124,78,9,114,96,213,134,33,189>>

keccakf1600_sha3:hash(sha3_512, <<"test">>).
% <<158,206,8,110,155,172,73,31,172,92,29,16,70,202,17,215,55,185,42,43,46,189,147,240,5,215,183,16,17,12,10,103,130,136,22,110,127,190,121,104,131,164,242,233,179,202,159,72,79,82,29,12,228,100,52,92,193,174,201,103,121,20,156,20>>
```

#### `keccakf1600_sha3:hash/3`

This function can be used for the following algorithms:

 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

These algorithms can output arbitrary length digests, so an output length must be specified.

```erlang
keccakf1600_sha3:hash(shake128, <<"test">>, 16).
% <<211,176,170,156,216,183,37,86,34,206,188,99,30,134,125,64>>

keccakf1600_sha3:hash(shake256, <<"test">>, 16).
% <<181,79,247,37,87,5,167,30,226,146,94,74,62,48,228,26>>
```

#### `keccakf1600_sha3:init/1`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)
 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

##### SHA3-224 (`sha3_224`)

```erlang
Sponge0 = keccakf1600_sha3:init(sha3_224).
% {sha3_224, #Ref<0.0.0.3>}
```

##### SHA3-256 (`sha3_256`)

```erlang
Sponge0 = keccakf1600_sha3:init(sha3_256).
% {sha3_256, #Ref<0.0.0.4>}
```

##### SHA3-384 (`sha3_384`)

```erlang
Sponge0 = keccakf1600_sha3:init(sha3_384).
% {sha3_384, #Ref<0.0.0.5>}
```

##### SHA3-512 (`sha3_512`)

```erlang
Sponge0 = keccakf1600_sha3:init(sha3_512).
% {sha3_512, #Ref<0.0.0.6>}
```

##### SHAKE128 (`shake128`)

```erlang
Sponge0 = keccakf1600_sha3:init(shake128).
% {shake128, #Ref<0.0.0.7>}
```

##### SHAKE256 (`shake256`)

```erlang
Sponge0 = keccakf1600_sha3:init(shake256).
% {shake256, #Ref<0.0.0.8>}
```

#### `keccakf1600_sha3:update/2`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)
 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

The examples below use the `Sponge0` for each algorithm from the examples above for `keccakf1600_sha3:init/1`.

##### SHA3-224 (`sha3_224`)

```erlang
Sponge1 = keccakf1600_sha3:update(Sponge0, <<"test">>).
% {sha3_224, #Ref<0.0.0.9>}
```

##### SHA3-256 (`sha3_256`)

```erlang
Sponge1 = keccakf1600_sha3:update(Sponge0, <<"test">>).
% {sha3_256, #Ref<0.0.0.10>}
```

##### SHA3-384 (`sha3_384`)

```erlang
Sponge1 = keccakf1600_sha3:update(Sponge0, <<"test">>).
% {sha3_384, #Ref<0.0.0.11>}
```

##### SHA3-512 (`sha3_512`)

```erlang
Sponge1 = keccakf1600_sha3:update(Sponge0, <<"test">>).
% {sha3_512, #Ref<0.0.0.12>}
```

##### SHAKE128 (`shake128`)

```erlang
Sponge1 = keccakf1600_sha3:update(Sponge0, <<"test">>).
% {shake128, #Ref<0.0.0.13>}
```

##### SHAKE256 (`shake256`)

```erlang
Sponge1 = keccakf1600_sha3:update(Sponge0, <<"test">>).
% {shake256, #Ref<0.0.0.14>}
```

#### `keccakf1600_sha3:final/2`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)

The examples below use the `Sponge1` for each algorithm from the examples above for `keccakf1600_sha3:update/2`.

##### SHA3-224 (`sha3_224`)

```erlang
Out = keccakf1600_sha3:final(Sponge1).
% <<55,151,191,10,251,191,202,74,123,187,167,96,42,43,85,39,70,135,101,23,167,249,183,206,45,176,174,123>>
```

##### SHA3-256 (`sha3_256`)

```erlang
Out = keccakf1600_sha3:final(Sponge1).
% <<54,240,40,88,11,176,44,200,39,42,154,2,15,66,0,227,70,226,118,174,102,78,69,238,128,116,85,116,226,245,171,128>>
```

##### SHA3-384 (`sha3_384`)

```erlang
Out = keccakf1600_sha3:final(Sponge1).
% <<229,22,218,187,35,182,227,0,38,134,53,67,40,39,128,163,174,13,204,240,85,81,207,2,149,23,141,127,240,241,180,30,236,185,219,63,242,25,0,124,78,9,114,96,213,134,33,189>>
```

##### SHA3-512 (`sha3_512`)

```erlang
Out = keccakf1600_sha3:final(Sponge1).
% <<158,206,8,110,155,172,73,31,172,92,29,16,70,202,17,215,55,185,42,43,46,189,147,240,5,215,183,16,17,12,10,103,130,136,22,110,127,190,121,104,131,164,242,233,179,202,159,72,79,82,29,12,228,100,52,92,193,174,201,103,121,20,156,20>>
```

#### `keccakf1600_sha3:final/3`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)

These algorithms can output arbitrary length digests, so an output length must be specified.

The examples below use the `Sponge1` for each algorithm from the examples above for `keccakf1600_sha3:update/2`.

##### SHAKE128 (`shake128`)

```erlang
Out = keccakf1600_sha3:final(Sponge1, 16).
% <<211,176,170,156,216,183,37,86,34,206,188,99,30,134,125,64>>
```

##### SHAKE256 (`shake256`)

```erlang
Out = keccakf1600_sha3:final(Sponge1, 16).
% <<181,79,247,37,87,5,167,30,226,146,94,74,62,48,228,26>>
```

