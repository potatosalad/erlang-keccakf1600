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

%% API
-export([start/0]).
-export([hash/2]).
-export([hash/3]).
-export([init/1]).
-export([update/2]).
-export([final/1]).
-export([final/2]).
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

-on_load(init/0).

%%%===================================================================
%%% API functions
%%%===================================================================

start() ->
	application:ensure_all_started(?MODULE).

hash(sha3_224, In) ->
	sha3_224(In);
hash(sha3_256, In) ->
	sha3_256(In);
hash(sha3_384, In) ->
	sha3_384(In);
hash(sha3_512, In) ->
	sha3_512(In);
hash(Type, In) ->
	erlang:error({badarg, [Type, In]}).

hash(shake128, In, Outlen) ->
	shake128(In, Outlen);
hash(shake256, In, Outlen) ->
	shake256(In, Outlen);
hash(Type, In, Outlen) ->
	erlang:error({badarg, [Type, In, Outlen]}).

init(sha3_224) ->
	sha3_224_init();
init(sha3_256) ->
	sha3_256_init();
init(sha3_384) ->
	sha3_384_init();
init(sha3_512) ->
	sha3_512_init();
init(shake128) ->
	shake128_init();
init(shake256) ->
	shake256_init();
init(Type) ->
	erlang:error({badarg, [Type]}).

update(State={sha3_224, _}, In) ->
	sha3_224_update(State, In);
update(State={sha3_256, _}, In) ->
	sha3_256_update(State, In);
update(State={sha3_384, _}, In) ->
	sha3_384_update(State, In);
update(State={sha3_512, _}, In) ->
	sha3_512_update(State, In);
update(State={shake128, _}, In) ->
	shake128_update(State, In);
update(State={shake256, _}, In) ->
	shake256_update(State, In);
update(State, In) ->
	erlang:error({badarg, [State, In]}).

final(State={sha3_224, _}) ->
	sha3_224_final(State);
final(State={sha3_256, _}) ->
	sha3_256_final(State);
final(State={sha3_384, _}) ->
	sha3_384_final(State);
final(State={sha3_512, _}) ->
	sha3_512_final(State);
final(State) ->
	erlang:error({badarg, [State]}).

final(State={shake128, _}, Outlen) ->
	shake128_final(State, Outlen);
final(State={shake256, _}, Outlen) ->
	shake256_final(State, Outlen);
final(State, Outlen) ->
	erlang:error({badarg, [State, Outlen]}).

%%%===================================================================
%%% SHA-3 API functions
%%%===================================================================

sha3_224(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% SHAKE API functions
%%%===================================================================

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

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
init() ->
	SoName = filename:join(priv_dir(), ?MODULE_STRING),
	erlang:load_nif(SoName, 0).

%% @private
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
