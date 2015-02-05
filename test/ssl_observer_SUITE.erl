
-module(ssl_observer_SUITE).

-include_lib("common_test/include/ct.hrl").

%% API
-compile(export_all).

-define(SSL_OPTS, [{mode, binary},
                   {verify, verify_none},
                   {active, false},
                   {packet, 0}
                  ]).

all() ->
    [
        {group, tracer}
    ].

groups() ->
    [{tracer, [], [all_ciphers_and_protocols]}].

suite() ->
    [].

handshake_finished(Reason, Version, Ciphers) ->
    ct:print("handshake=~p, version=~p, ciphers=~p",[Reason, Version, Ciphers]).

%%%===================================================================
%%% Init & teardown
%%%===================================================================

init_per_suite(Config) ->
    ensure_all_started(ssl_observer),
    start_ssl_server(Config).

end_per_suite(Config) ->

    Config.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_CaseName, Config) ->
    Config.

end_per_testcase(_CaseName, Config) ->
    Config.

all_ciphers_and_protocols(Config) ->
    meck:new(test_callback, [non_strict]),
    OkSpec = [ok, '_', '_'],
    ProtocolErrorSpec = [{70, '_'}, '_', '_'],
    CipherErrorSpec = [{71, '_'}, '_', '_'],
    meck:expect(test_callback, handshake_finished, [{OkSpec, ok}, {CipherErrorSpec, ok}, {ProtocolErrorSpec, ok}]),
    ssl_observer:add_callback_module(test_callback),
    erlang:link(erlang:whereis(ssl_tracer)),
    Port = ?config(port, Config),
    Host = "127.0.0.1",
    F = fun(Cipher, Version) ->
        ssl:connect(Host, Port,[{mode, binary},
                                {verify, verify_none},
                                {active, false},
                                {packet, 0},
                                {versions, [Version]},
                                {ciphers, [Cipher]}], 6000) end,

    Ciphers = ssl:cipher_suites(),
    Versions = [sslv3, 'tlsv1.2','tlsv1.1',tlsv1],
    CipherConn = [{Version, Cipher, F(Cipher, Version)} || Cipher <- Ciphers, Version <- Versions],

    Allowed = [{Version, Cipher} || {Version, Cipher, {ok, Socket}} <- CipherConn],
    Disallowed = [{Version, Cipher} || {Version, Cipher, {error, _}} <- CipherConn],

    [ssl:close(Socket) || {_, _, {ok, Socket}} <- CipherConn],

    AllowedLen = length(Allowed),
    AllowedLen = meck:num_calls(test_callback, handshake_finished, OkSpec),

    CiphersLen = length(Ciphers),
    ProtocolErrors = CiphersLen, %% every cipher with sslv3

    ProtocolErrors = meck:num_calls(test_callback, handshake_finished, ProtocolErrorSpec),

    DisallowedLen = length(Disallowed),
    CiperErrors = DisallowedLen - ProtocolErrors,

    CiperErrors = meck:num_calls(test_callback, handshake_finished, CipherErrorSpec),

    meck:unload(),

    ok.

successfull(Config) ->
    Port = ?config(port, Config),
    {ok, Socket} = ssl:connect("127.0.0.1", Port, ?SSL_OPTS, 6000),
    ssl:close(Socket).

ensure_all_started(App) ->
    case erlang:function_exported(application, ensure_all_started, 1) of
        true ->
            application:ensure_all_started(ssl_observer);
        _ ->
            do_ensure_all_started(App)
    end,
    ok = application:start(ranch).

do_ensure_all_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok;
        {error,{not_started,DepApp}} ->
            do_ensure_all_started(DepApp),
            do_ensure_all_started(App)
    end.

start_ssl_server(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    KeyFile = filename:join(DataDir, "key.pem"),
    CertFile = filename:join(DataDir, "cert.pem"),

    {ok, Pid} = ranch:start_listener(ssl_echo, 5,
        ranch_ssl, [
            {port, 0},
            {keyfile, KeyFile},
            {certfile, CertFile},
            {versions, [tlsv1,'tlsv1.1', 'tlsv1.2']}
        ],
        echo_protocol, []
    ),

    Port = ranch:get_port(ssl_echo),
    [{port, Port}, {ranch_pid, Pid} | Config].

