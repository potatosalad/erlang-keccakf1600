# Keccak-f[1600] asynchronous port driver

[![Build Status](https://travis-ci.org/potatosalad/erlang-keccakf1600.png?branch=master)](https://travis-ci.org/potatosalad/erlang-keccakf1600) [![Hex.pm](https://img.shields.io/hexpm/v/keccakf1600.svg)](https://hex.pm/packages/keccakf1600)

[Keccak-f[1600]](http://keccak.noekeon.org/) asynchronous port driver for Erlang and Elixir.

## Installation

Add `keccakf1600` to your project's dependencies in `mix.exs`

```elixir
defp deps do
  [
    {:keccakf1600, "~> 0.0.1"}
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

```erlang
keccakf1600_fips202:shake128(<<"test">>, 16).
% <<211,176,170,156,216,183,37,86,34,206,188,99,30,134,125,64>>

keccakf1600_fips202:shake256(<<"test">>, 16).
% <<181,79,247,37,87,5,167,30,226,146,94,74,62,48,228,26>>

keccakf1600_fips202:sha3_224(<<"test">>).
% <<55,151,191,10,251,191,202,74,123,187,167,96,42,43,85,39,70,135,101,23,167,249,183,206,45,176,174,123>>

keccakf1600_fips202:sha3_256(<<"test">>).
% <<54,240,40,88,11,176,44,200,39,42,154,2,15,66,0,227,70,226,118,174,102,78,69,238,128,116,85,116,226,245,171,128>>

keccakf1600_fips202:sha3_384(<<"test">>).
% <<229,22,218,187,35,182,227,0,38,134,53,67,40,39,128,163,174,13,204,240,85,81,207,2,149,23,141,127,240,241,180,30,236,185,219,63,242,25,0,124,78,9,114,96,213,134,33,189>>

keccakf1600_fips202:sha3_512(<<"test">>).
% <<158,206,8,110,155,172,73,31,172,92,29,16,70,202,17,215,55,185,42,43,46,189,147,240,5,215,183,16,17,12,10,103,130,136,22,110,127,190,121,104,131,164,242,233,179,202,159,72,79,82,29,12,228,100,52,92,193,174,201,103,121,20,156,20>>
```
