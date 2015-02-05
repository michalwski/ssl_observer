%%%-------------------------------------------------------------------
%% @doc ssl_tracer tracks every handshake
%% and provides feedback to callback module
%% @end
%%%-------------------------------------------------------------------

-module(ssl_tracer).

%% API
-export([start_link/0]).
-export([add_callback_module/1]).

%% proc callbacks
-export([init/1,
         system_continue/3,
         system_terminate/4,
         system_get_state/1,
         system_replace_state/2]).

-define(SERVER, ?MODULE).

-record(state, {handshakes = dict:new(),
                callbacks = [],
                tls_connection_sup}).

-include_lib("ssl/src/tls_handshake.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
    {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
    proc_lib:start_link(?MODULE, init, [self()]).

add_callback_module(Module) ->
    Pid = erlang:whereis(?SERVER),
    Pid ! {add_callback_module, Module}.

init(Parent) ->
    register(?SERVER, self()),
    proc_lib:init_ack(Parent, {ok, self()}),
    process_flag(trap_exit, true),
    Deb = sys:debug_options([]),
    TLSConnectionSup = start_tracing(),
    loop(Parent, #state{tls_connection_sup = TLSConnectionSup}, Deb).

loop(Parent, #state{tls_connection_sup = TLSConnSup} = State, Deb) ->
    receive
        {system, From, Request} ->
            sys:handle_system_msg(Request, From, Parent,
                                  ?MODULE, Deb, State);
        {trace, Pid, call, Call} ->
            NewState = handle_trace_call(Pid, Call, State),
            loop(Parent, NewState, Deb);
        {trace, Pid, return_from, Function, Result} ->
            NewState = handle_trace_return_from(Pid, Function, Result, State),
            loop(Parent, NewState, Deb);
        {trace, _Pid, return_to, _} ->
            %% not interesting here
            loop(Parent, State, Deb);
        {add_callback_module, Module} ->
            Callbacks = State#state.callbacks,
            loop(Parent, State#state{callbacks = [Module | Callbacks]}, Deb);
        {'EXIT', Parent, Reason} ->
            system_terminate(Reason, Parent, Deb, State);
        {'EXIT', TLSConnSup, Reason} ->
            system_terminate({tls_connection_sup, Reason}, Parent, Deb, State);
        _Msg ->
            %% ignore other messages
            loop(Parent, State, Deb)
    after 5000 ->
        check_tracing(),
        loop(Parent, State, Deb)
    end.

system_continue(Parent, Deb, State) ->
    loop(Parent, State, Deb).

system_terminate(Reason, _Parent, _Deb, #state{tls_connection_sup = TLSConnectionSup}) ->
    unset_tracepattern(),
    set_tracing(TLSConnectionSup, false, erlang:whereis(?SERVER)),
    exit(Reason).

system_get_state(State) ->
    {ok, State}.

system_replace_state(StateFun, State) ->
    NState = StateFun(State),
    {ok, NState, NState}.

handle_trace_call(Pid, {tls_handshake, hello,
                         [#client_hello{client_version = Version,
                                        cipher_suites = CipherSuites},
                          _, _, _]},
                  #state{handshakes = Handshakes} = State) ->
    NewHandshakes = dict:store(Pid, {Version, CipherSuites}, Handshakes),
    State#state{handshakes = NewHandshakes};

handle_trace_call(_Pid, _Call, State) ->
    State.

handle_trace_return_from(Pid, {tls_handshake,hello,4}, Result,
                         #state{handshakes = Handshakes,
                                callbacks = Callbacks} = State) ->

    case Result of
        {alert, _, Code, _} = Alert ->
            {VersionRaw, CiphersBin} = dict:fetch(Pid, Handshakes),
            Version = tls_record:protocol_version(VersionRaw),
            Ciphers = [ssl:suite_definition(CipherBin) || CipherBin <- CiphersBin],
            Reason = ssl_alert:reason_code(Alert, ok),
            notify_handshake({Code, Reason}, Version, Ciphers, Callbacks);
        {Version, {_Type, #session{cipher_suite = CipherSuite} = _Session}, _ConnectionStates, _ServerHelloExt} ->
            notify_handshake(ok, tls_record:protocol_version(Version),
                             ssl:suite_definition(CipherSuite), Callbacks);
        _ ->
            ok
    end,
    State#state{handshakes = dict:erase(Pid, Handshakes)};
handle_trace_return_from(_Pid, _Function, _Result, State) ->
    State.

start_tracing() ->
    TLSConnectionSup = erlang:whereis(tls_connection_sup),
    erlang:link(TLSConnectionSup),
    TLSTracer = erlang:whereis(?SERVER),
    set_tracing(TLSConnectionSup, true, TLSTracer),
    code:ensure_loaded(tls_handshake),
    set_tracepattern(),
    TLSConnectionSup.

check_tracing() ->
    case erlang:trace_info({tls_handshake, hello, 4}, match_spec) of
        {match_spec, R} when R =:= false; R =:= undefined ->
            set_tracepattern();
        _ ->
            ok
    end.

set_tracepattern() ->
    MS = [{'_',[],[{return_trace}]}],
    erlang:trace_pattern({tls_handshake, hello, '_'}, MS, [local]).

unset_tracepattern() ->
    erlang:trace_pattern({tls_handshake, hello, '_'}, false, [local]).

notify_handshake(Reason, Version, Ciphers, Callbacks) ->
    F = fun(Module) ->
        Module:handshake_finished(Reason, Version, Ciphers)
    end,
    lists:foreach(F, Callbacks).

set_tracing(TLSConnectionSup, How, TLSTracer) ->
    erlang:trace(TLSConnectionSup, How,
                 [set_on_spawn, call, return_to, {tracer, TLSTracer}]).
