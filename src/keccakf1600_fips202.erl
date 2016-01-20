%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jan 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(keccakf1600_fips202).

-define(NAMESPACE, fips202).

%% API
-export([shake128/2]).
-export([shake256/2]).
-export([sha3_224/1]).
-export([sha3_256/1]).
-export([sha3_384/1]).
-export([sha3_512/1]).

%%%===================================================================
%%% API
%%%===================================================================

shake128(InputBytes, OutputByteLen)
		when is_binary(InputBytes)
		andalso is_integer(OutputByteLen)
		andalso OutputByteLen >= 0 ->
	call(shake128, {InputBytes, OutputByteLen}).

shake256(InputBytes, OutputByteLen)
		when is_binary(InputBytes)
		andalso is_integer(OutputByteLen)
		andalso OutputByteLen >= 0 ->
	call(shake256, {InputBytes, OutputByteLen}).

sha3_224(InputBytes)
		when is_binary(InputBytes) ->
	call(sha3_224, {InputBytes}).

sha3_256(InputBytes)
		when is_binary(InputBytes) ->
	call(sha3_256, {InputBytes}).

sha3_384(InputBytes)
		when is_binary(InputBytes) ->
	call(sha3_384, {InputBytes}).

sha3_512(InputBytes)
		when is_binary(InputBytes) ->
	call(sha3_512, {InputBytes}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	keccakf1600:call(?NAMESPACE, Function, Arguments).
