%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jan 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(cavp_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([fips202/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, 'keccaktestvectors'}
	].

groups() ->
	[
		{'keccaktestvectors', [], [
			fips202
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(keccakf1600),
	data_setup(Config).

end_per_suite(_Config) ->
	_ = application:stop(keccakf1600),
	ok.

init_per_group('keccaktestvectors', Config) ->
	Folder = data_file("keccaktestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{fips202_files, Files} | Config].

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

fips202(Config) ->
	Files = [File || File <- ?config(fips202_files, Config)],
	lists:foldl(fun fips202/2, Config, Files).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
data_setup(Config) ->
	lists:foldl(fun(F, C) ->
		data_setup(F, C)
	end, Config, [
		"keccaktestvectors"
	]).

%% @private
data_setup(F = "keccaktestvectors", Config) ->
	BaseURL = "https://raw.githubusercontent.com/gvanas/KeccakCodePackage/1893f17c8029d0e6423f1fa4de4d15f76b188a27/TestVectors/",
	Files = [
		"ShortMsgKAT_SHA3-224.txt",
		"ShortMsgKAT_SHA3-256.txt",
		"ShortMsgKAT_SHA3-384.txt",
		"ShortMsgKAT_SHA3-512.txt",
		"ShortMsgKAT_SHAKE128.txt",
		"ShortMsgKAT_SHAKE256.txt"
	],
	URLs = [BaseURL ++ File || File <- Files],
	Directory = data_file(F, Config),
	DataFiles = [data_file(filename:join(F, File), Config) || File <- Files],
	ok = data_setup_multiple(DataFiles, Directory, URLs),
	Config.

%% @private
data_setup_multiple([DataFile | DataFiles], Directory, [URL | URLs]) ->
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end,
	case filelib:is_file(DataFile) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(URL, DataFile)
	end,
	data_setup_multiple(DataFiles, Directory, URLs);
data_setup_multiple([], _Directory, []) ->
	ok.

%% @private
fips202(File, Config) ->
	Options = case iolist_to_binary(filename:basename(File)) of
		<< "ShortMsgKAT_SHA3-", BitsBin:3/binary, _/binary >> ->
			Bits = binary_to_integer(BitsBin),
			Bytes = (Bits + 7) div 8,
			Type = list_to_atom("sha3_" ++ integer_to_list(Bits)),
			Arity = 1,
			{Type, Arity, Bytes};
		<< "ShortMsgKAT_SHAKE", BitsBin:3/binary, _/binary >> ->
			Bits = binary_to_integer(BitsBin),
			Bytes = 512,
			Type = list_to_atom("shake" ++ integer_to_list(Bits)),
			Arity = 2,
			{Type, Arity, Bytes}
	end,
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [filename:basename(File)]),
	fips202(Vectors, Options, Config).

%% @private
fips202([
			{vector, {<<"Len">>, Len}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"MD">>, MD}, _}
			| Vectors
		], {Type, Arity=1, OutputByteLen}, Config) when Len rem 8 =:= 0 ->
	InputBytes = binary:part(Msg, 0, Len div 8),
	?tv_ok(T0, keccakf1600, hash, [Type, InputBytes], MD),
	Sponge0 = keccakf1600:init(Type),
	Sponge1 = keccakf1600:update(Sponge0, InputBytes),
	?tv_ok(T1, keccakf1600, final, [Sponge1], MD),
	fips202(Vectors, {Type, Arity, OutputByteLen}, Config);
fips202([
			{vector, {<<"Len">>, Len}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"Squeezed">>, Squeezed}, _}
			| Vectors
		], {Type, Arity=2, OutputByteLen}, Config) when Len rem 8 =:= 0 ->
	InputBytes = binary:part(Msg, 0, Len div 8),
	?tv_ok(T0, keccakf1600, hash, [Type, InputBytes, OutputByteLen], Squeezed),
	Sponge0 = keccakf1600:init(Type),
	Sponge1 = keccakf1600:update(Sponge0, InputBytes),
	?tv_ok(T1, keccakf1600, final, [Sponge1, OutputByteLen], Squeezed),
	fips202(Vectors, {Type, Arity, OutputByteLen}, Config);
fips202([
			{vector, {<<"Len">>, _Len}, _},
			{vector, {<<"Msg">>, _Msg}, _},
			{vector, {<<"MD">>, _MD}, _}
			| Vectors
		], Options, Config) ->
	fips202(Vectors, Options, Config);
fips202([
			{vector, {<<"Len">>, _Len}, _},
			{vector, {<<"Msg">>, _Msg}, _},
			{vector, {<<"Squeezed">>, _Squeezed}, _}
			| Vectors
		], Options, Config) ->
	fips202(Vectors, Options, Config);
fips202([], _Opts, _Config) ->
	ok.
