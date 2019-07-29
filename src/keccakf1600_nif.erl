%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2019, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  28 July 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(keccakf1600_nif).

%% decaf/shake.h
% SHA-3 API
-export([sha3_224/2]).
-export([sha3_224_init/0]).
-export([sha3_224_update/2]).
-export([sha3_224_final/2]).
-export([sha3_256/2]).
-export([sha3_256_init/0]).
-export([sha3_256_update/2]).
-export([sha3_256_final/2]).
-export([sha3_384/2]).
-export([sha3_384_init/0]).
-export([sha3_384_update/2]).
-export([sha3_384_final/2]).
-export([sha3_512/2]).
-export([sha3_512_init/0]).
-export([sha3_512_update/2]).
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

-on_load(init/0).

%%%===================================================================
%%% decaf/shake.h
%%%===================================================================

%% SHA-3 API functions

sha3_224(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%% SHAKE API functions

shake128(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/spongerng.h
%%%===================================================================

spongerng_init_from_buffer(_In, _Deterministic) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_init_from_file(_File, _Inlen, _Deterministic) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_init_from_dev_urandom() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_next(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_stir(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
init() ->
	SoName = filename:join(keccakf1600:priv_dir(), ?MODULE_STRING),
	erlang:load_nif(SoName, 0).
