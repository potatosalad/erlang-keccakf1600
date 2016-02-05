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
-module(keccakf1600).

-include("keccakf1600.hrl").

%% API
-export([start/0]).
-export([call/2]).
-export([call/3]).
-export([call/4]).
-export([open/0]).
-export([close/1]).
%% SHA-3 API
-export([sha3_224/1]).
-export([sha3_224_init/0]).
-export([sha3_224_update/2]).
-export([sha3_224_final/1]).
-export([sha3_256/1]).
-export([sha3_256_init/0]).
-export([sha3_256_update/2]).
-export([sha3_256_final/1]).
-export([sha3_384/1]).
-export([sha3_384_init/0]).
-export([sha3_384_update/2]).
-export([sha3_384_final/1]).
-export([sha3_512/1]).
-export([sha3_512_init/0]).
-export([sha3_512_update/2]).
-export([sha3_512_final/1]).
%% SHAKE API
-export([shake128/2]).
-export([shake128_init/0]).
-export([shake128_update/2]).
-export([shake128_final/2]).
-export([shake256/2]).
-export([shake256_init/0]).
-export([shake256_update/2]).
-export([shake256_final/2]).

%% MAcros
-define(MAX_BYTES, 20000). %% Current value is: erlang:system_info(context_reductions) * 10
-define(MAYBE_START_KECCAKF1600(F), try
	F
catch
	_:_ ->
		_ = keccakf1600:start(),
		F
end).

%%%===================================================================
%%% API functions
%%%===================================================================

start() ->
	application:ensure_all_started(?MODULE).

call(Namespace, Function)
		when is_atom(Namespace)
		andalso is_atom(Function) ->
	?MAYBE_START_KECCAKF1600(call(Namespace, Function, {})).

call(Namespace, Function, Arguments)
		when is_atom(Namespace)
		andalso is_atom(Function)
		andalso is_tuple(Arguments) ->
	?MAYBE_START_KECCAKF1600(call(erlang:whereis(?KECCAKF1600_DRIVER_ATOM), Namespace, Function, Arguments)).

call(Port, Namespace, Function, Arguments)
		when is_port(Port)
		andalso is_atom(Namespace)
		andalso is_atom(Function)
		andalso is_tuple(Arguments) ->
	driver_call(Port, ?KECCAKF1600_ASYNC_CALL, Namespace, Function, Arguments).

open() ->
	erlang:open_port({spawn_driver, ?KECCAKF1600_DRIVER_NAME}, [binary]).

close(P) ->
	try
		true = erlang:port_close(P),
		receive
			{'EXIT', P, _} ->
				ok
		after
			0 ->
				ok
		end
	catch
		_:_ ->
			erlang:error(badarg)
	end.

%%%===================================================================
%%% SHA-3 API functions
%%%===================================================================

sha3_224(InputBytes)
		when is_binary(InputBytes) ->
	sha3(sha3_224, InputBytes, byte_size(InputBytes), ?MAX_BYTES).

sha3_224_init() ->
	{sha3_224, keccakf1600_sha3_224:init()}.

sha3_224_update(State={sha3_224, Sponge}, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	sha3_update(State, In, byte_size(In), ?MAX_BYTES).

sha3_224_final({sha3_224, Sponge})
		when is_binary(Sponge) ->
	keccakf1600_sha3_224:final(Sponge).

sha3_256(InputBytes)
		when is_binary(InputBytes) ->
	sha3(sha3_256, InputBytes, byte_size(InputBytes), ?MAX_BYTES).

sha3_256_init() ->
	{sha3_256, keccakf1600_sha3_256:init()}.

sha3_256_update(State={sha3_256, Sponge}, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	sha3_update(State, In, byte_size(In), ?MAX_BYTES).

sha3_256_final({sha3_256, Sponge})
		when is_binary(Sponge) ->
	keccakf1600_sha3_256:final(Sponge).

sha3_384(InputBytes)
		when is_binary(InputBytes) ->
	sha3(sha3_384, InputBytes, byte_size(InputBytes), ?MAX_BYTES).

sha3_384_init() ->
	{sha3_384, keccakf1600_sha3_384:init()}.

sha3_384_update(State={sha3_384, Sponge}, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	sha3_update(State, In, byte_size(In), ?MAX_BYTES).

sha3_384_final({sha3_384, Sponge})
		when is_binary(Sponge) ->
	keccakf1600_sha3_384:final(Sponge).

sha3_512(InputBytes)
		when is_binary(InputBytes) ->
	sha3(sha3_512, InputBytes, byte_size(InputBytes), ?MAX_BYTES).

sha3_512_init() ->
	{sha3_512, keccakf1600_sha3_512:init()}.

sha3_512_update(State={sha3_512, Sponge}, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	sha3_update(State, In, byte_size(In), ?MAX_BYTES).

sha3_512_final({sha3_512, Sponge})
		when is_binary(Sponge) ->
	keccakf1600_sha3_512:final(Sponge).

%%%===================================================================
%%% SHAKE API functions
%%%===================================================================

shake128(InputBytes, OutputByteLen)
		when is_binary(InputBytes)
		andalso is_integer(OutputByteLen)
		andalso OutputByteLen >= 0 ->
	shake(shake128, InputBytes, OutputByteLen, byte_size(InputBytes), ?MAX_BYTES).

shake128_init() ->
	{shake128, keccakf1600_shake128:init()}.

shake128_update(State={shake128, Sponge}, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	shake_update(State, In, byte_size(In), ?MAX_BYTES).

shake128_final({shake128, Sponge}, OutputByteLen)
		when is_binary(Sponge)
		andalso is_integer(OutputByteLen)
		andalso OutputByteLen >= 0 ->
	keccakf1600_shake128:final(Sponge, OutputByteLen).

shake256(InputBytes, OutputByteLen)
		when is_binary(InputBytes)
		andalso is_integer(OutputByteLen)
		andalso OutputByteLen >= 0 ->
	shake(shake256, InputBytes, OutputByteLen, byte_size(InputBytes), ?MAX_BYTES).

shake256_init() ->
	{shake256, keccakf1600_shake256:init()}.

shake256_update(State={shake256, Sponge}, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	shake_update(State, In, byte_size(In), ?MAX_BYTES).

shake256_final({shake256, Sponge}, OutputByteLen)
		when is_binary(Sponge)
		andalso is_integer(OutputByteLen)
		andalso OutputByteLen >= 0 ->
	keccakf1600_shake256:final(Sponge, OutputByteLen).

%%%-------------------------------------------------------------------
%%% Internal SHA-3 functions
%%%-------------------------------------------------------------------

%% @private
sha3(SHA3Function, In, Inlen, MaxSize) when Inlen =< MaxSize ->
	keccakf1600_fips202:SHA3Function(In);
sha3(SHA3Function, In, Inlen, MaxSize) ->
	sha3_final(sha3_update(sha3_init(SHA3Function), In, Inlen, MaxSize)).

%% @private
sha3_init(H=sha3_224) ->
	{H, keccakf1600_sha3_224:init()};
sha3_init(H=sha3_256) ->
	{H, keccakf1600_sha3_256:init()};
sha3_init(H=sha3_384) ->
	{H, keccakf1600_sha3_384:init()};
sha3_init(H=sha3_512) ->
	{H, keccakf1600_sha3_512:init()}.

%% @private
sha3_update({H=sha3_224, Sponge}, In) ->
	{H, keccakf1600_sha3_224:update(Sponge, In)};
sha3_update({H=sha3_256, Sponge}, In) ->
	{H, keccakf1600_sha3_256:update(Sponge, In)};
sha3_update({H=sha3_384, Sponge}, In) ->
	{H, keccakf1600_sha3_384:update(Sponge, In)};
sha3_update({H=sha3_512, Sponge}, In) ->
	{H, keccakf1600_sha3_512:update(Sponge, In)}.

%% @private
sha3_update(State, In, Inlen, MaxSize) when Inlen =< MaxSize ->
	sha3_update(State, In);
sha3_update(State, In, _Inlen, MaxSize) ->
	<< Slice:MaxSize/binary, Rest/binary >> = In,
	sha3_update(sha3_update(State, Slice), Rest, byte_size(Rest), MaxSize).

%% @private
sha3_final({sha3_224, Sponge}) ->
	keccakf1600_sha3_224:final(Sponge);
sha3_final({sha3_256, Sponge}) ->
	keccakf1600_sha3_256:final(Sponge);
sha3_final({sha3_384, Sponge}) ->
	keccakf1600_sha3_384:final(Sponge);
sha3_final({sha3_512, Sponge}) ->
	keccakf1600_sha3_512:final(Sponge).

%%%-------------------------------------------------------------------
%%% Internal SHAKE functions
%%%-------------------------------------------------------------------

%% @private
shake(SHAKEFunction, In, Outlen, Inlen, MaxSize) when Inlen =< MaxSize ->
	keccakf1600_fips202:SHAKEFunction(In, Outlen);
shake(SHAKEFunction, In, Outlen, Inlen, MaxSize) ->
	shake_final(shake_update(shake_init(SHAKEFunction), In, Inlen, MaxSize), Outlen).

%% @private
shake_init(H=shake128) ->
	{H, keccakf1600_shake128:init()};
shake_init(H=shake256) ->
	{H, keccakf1600_shake256:init()}.

%% @private
shake_update({H=shake128, Sponge}, In) ->
	{H, keccakf1600_shake128:update(Sponge, In)};
shake_update({H=shake256, Sponge}, In) ->
	{H, keccakf1600_shake256:update(Sponge, In)}.

%% @private
shake_update(State, In, Inlen, MaxSize) when Inlen =< MaxSize ->
	shake_update(State, In);
shake_update(State, In, _Inlen, MaxSize) ->
	<< Slice:MaxSize/binary, Rest/binary >> = In,
	shake_update(shake_update(State, Slice), Rest, byte_size(Rest), MaxSize).

%% @private
shake_final({shake128, Sponge}, Outlen) ->
	keccakf1600_shake128:final(Sponge, Outlen);
shake_final({shake256, Sponge}, Outlen) ->
	keccakf1600_shake256:final(Sponge, Outlen).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
driver_call(Port, Command, Namespace, Function, Arguments) ->
	Tag = erlang:make_ref(),
	case erlang:port_call(Port, Command, {Tag, Namespace, Function, Arguments}) of
		Tag ->
			receive
				{Tag, Reply} ->
					Reply
			end;
		{Tag, Error} ->
			Error
	end.
