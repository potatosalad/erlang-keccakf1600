%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  04 Feb 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(keccakf1600_shake128).

-define(NAMESPACE, shake128).

%% API
-export([init/0]).
-export([update/2]).
-export([final/2]).

%%%===================================================================
%%% API
%%%===================================================================

init() ->
	call(init).

update(Sponge, In)
		when is_binary(Sponge)
		andalso is_binary(In) ->
	call(update, {Sponge, In}).

final(Sponge, Outlen)
		when is_binary(Sponge)
		andalso is_integer(Outlen)
		andalso Outlen >= 0 ->
	call(final, {Sponge, Outlen}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	keccakf1600:call(?NAMESPACE, Function).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	keccakf1600:call(?NAMESPACE, Function, Arguments).
