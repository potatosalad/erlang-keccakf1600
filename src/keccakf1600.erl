%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2019, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(keccakf1600).

%% API
-export([start/0]).
%% Legacy API
-export([hash/2]).
-export([hash/3]).
-export([init/1]).
-export([update/2]).
-export([final/1]).
-export([final/2]).
%% decaf/shake.h
% SHA-3 API
-export([sha3_224/1]).
-export([sha3_224/2]).
-export([sha3_224_init/0]).
-export([sha3_224_update/2]).
-export([sha3_224_final/1]).
-export([sha3_224_final/2]).
-export([sha3_256/1]).
-export([sha3_256/2]).
-export([sha3_256_init/0]).
-export([sha3_256_update/2]).
-export([sha3_256_final/1]).
-export([sha3_256_final/2]).
-export([sha3_384/1]).
-export([sha3_384/2]).
-export([sha3_384_init/0]).
-export([sha3_384_update/2]).
-export([sha3_384_final/1]).
-export([sha3_384_final/2]).
-export([sha3_512/1]).
-export([sha3_512/2]).
-export([sha3_512_init/0]).
-export([sha3_512_update/2]).
-export([sha3_512_final/1]).
-export([sha3_512_final/2]).
% SHAKE API
-export([shake128/2]).
-export([shake128_init/0]).
-export([shake128_update/2]).
-export([shake128_final/2]).
-export([shake256/2]).
-export([shake256_init/0]).
-export([shake256_update/2]).
-export([shake256_final/2]).
%% decaf/spongerng.h
-export([spongerng_init_from_buffer/2]).
-export([spongerng_init_from_file/3]).
-export([spongerng_init_from_dev_urandom/0]).
-export([spongerng_next/2]).
-export([spongerng_stir/2]).
%% Internal API
-export([priv_dir/0]).

%%%===================================================================
%%% API functions
%%%===================================================================

start() ->
	application:ensure_all_started(?MODULE).

%%%===================================================================
%%% Legacy API functions
%%%===================================================================

%% @deprecated Please use the function {@link keccakf1600_sha3:hash/2} instead.
hash(T, In)
		when T =:= sha3_224
		orelse T =:= sha3_256
		orelse T =:= sha3_384
		orelse T =:= sha3_512 ->
	keccakf1600_sha3:hash(T, In).

%% @deprecated Please use the function {@link keccakf1600_sha3:hash/3} instead.
hash(T, In, Outlen)
		when T =:= sha3_224
		orelse T =:= sha3_256
		orelse T =:= sha3_384
		orelse T =:= sha3_512
		orelse T =:= shake128
		orelse T =:= shake256 ->
	keccakf1600_sha3:hash(T, In, Outlen).

%% @deprecated Please use the function {@link keccakf1600_sha3:init/1} instead.
init(T)
		when T =:= sha3_224
		orelse T =:= sha3_256
		orelse T =:= sha3_384
		orelse T =:= sha3_512
		orelse T =:= shake128
		orelse T =:= shake256 ->
	keccakf1600_sha3:init(T).

%% @deprecated Please use the function {@link keccakf1600_sha3:update/2} instead.
update(Context = {T, _}, In)
		when T =:= sha3_224
		orelse T =:= sha3_256
		orelse T =:= sha3_384
		orelse T =:= sha3_512
		orelse T =:= shake128
		orelse T =:= shake256 ->
	keccakf1600_sha3:update(Context, In).

%% @deprecated Please use the function {@link keccakf1600_sha3:final/1} instead.
final(Context = {T, _})
		when T =:= sha3_224
		orelse T =:= sha3_256
		orelse T =:= sha3_384
		orelse T =:= sha3_512 ->
	keccakf1600_sha3:final(Context).

%% @deprecated Please use the function {@link keccakf1600_sha3:final/2} instead.
final(Context = {T, _}, Outlen)
		when T =:= sha3_224
		orelse T =:= sha3_256
		orelse T =:= sha3_384
		orelse T =:= sha3_512
		orelse T =:= shake128
		orelse T =:= shake256 ->
	keccakf1600_sha3:final(Context, Outlen).

%%%===================================================================
%%% decaf/shake.h
%%%===================================================================

%% SHA-3 API functions

sha3_224(In) ->
	sha3_224(In, 28).

sha3_224(In, Outlen) ->
	keccakf1600_nif:sha3_224(In, Outlen).

sha3_224_init() ->
	keccakf1600_nif:sha3_224_init().

sha3_224_update(State, In) ->
	keccakf1600_nif:sha3_224_update(State, In).

sha3_224_final(State) ->
	sha3_224_final(State, 28).

sha3_224_final(State, Outlen) ->
	keccakf1600_nif:sha3_224_final(State, Outlen).

sha3_256(In) ->
	sha3_256(In, 32).

sha3_256(In, Outlen) ->
	keccakf1600_nif:sha3_256(In, Outlen).

sha3_256_init() ->
	keccakf1600_nif:sha3_256_init().

sha3_256_update(State, In) ->
	keccakf1600_nif:sha3_256_update(State, In).

sha3_256_final(State) ->
	sha3_256_final(State, 32).

sha3_256_final(State, Outlen) ->
	keccakf1600_nif:sha3_256_final(State, Outlen).

sha3_384(In) ->
	sha3_384(In, 48).

sha3_384(In, Outlen) ->
	keccakf1600_nif:sha3_384(In, Outlen).

sha3_384_init() ->
	keccakf1600_nif:sha3_384_init().

sha3_384_update(State, In) ->
	keccakf1600_nif:sha3_384_update(State, In).

sha3_384_final(State) ->
	sha3_384_final(State, 48).

sha3_384_final(State, Outlen) ->
	keccakf1600_nif:sha3_384_final(State, Outlen).

sha3_512(In) ->
	sha3_512(In, 64).

sha3_512(In, Outlen) ->
	keccakf1600_nif:sha3_512(In, Outlen).

sha3_512_init() ->
	keccakf1600_nif:sha3_512_init().

sha3_512_update(State, In) ->
	keccakf1600_nif:sha3_512_update(State, In).

sha3_512_final(State) ->
	sha3_512_final(State, 64).

sha3_512_final(State, Outlen) ->
	keccakf1600_nif:sha3_512_final(State, Outlen).

%% SHAKE API functions

shake128(In, Outlen) ->
	keccakf1600_nif:shake128(In, Outlen).

shake128_init() ->
	keccakf1600_nif:shake128_init().

shake128_update(State, In) ->
	keccakf1600_nif:shake128_update(State, In).

shake128_final(State, Outlen) ->
	keccakf1600_nif:shake128_final(State, Outlen).

shake256(In, Outlen) ->
	keccakf1600_nif:shake256(In, Outlen).

shake256_init() ->
	keccakf1600_nif:shake256_init().

shake256_update(State, In) ->
	keccakf1600_nif:shake256_update(State, In).

shake256_final(State, Outlen) ->
	keccakf1600_nif:shake256_final(State, Outlen).

%%%===================================================================
%%% decaf/spongerng.h
%%%===================================================================

spongerng_init_from_buffer(In, Deterministic) ->
	keccakf1600_nif:spongerng_init_from_buffer(In, Deterministic).

spongerng_init_from_file(File, Inlen, Deterministic) ->
	keccakf1600_nif:spongerng_init_from_file(File, Inlen, Deterministic).

spongerng_init_from_dev_urandom() ->
	keccakf1600_nif:spongerng_init_from_dev_urandom().

spongerng_next(State, Outlen) ->
	keccakf1600_nif:spongerng_next(State, Outlen).

spongerng_stir(State, In) ->
	keccakf1600_nif:spongerng_stir(State, In).

%%%===================================================================
%%% Internal API Functions
%%%===================================================================

-spec priv_dir() -> file:filename_all().
priv_dir() ->
	case code:priv_dir(?MODULE) of
		{error, bad_name} ->
			case code:which(?MODULE) of
				Filename when is_list(Filename) ->
					filename:join([filename:dirname(Filename), "../priv"]);
				_ ->
					"../priv"
			end;
		Dir ->
			Dir
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
