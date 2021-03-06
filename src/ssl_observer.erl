%%%-------------------------------------------------------------------
%% @doc ssl_observer public API
%% @end
%%%-------------------------------------------------------------------

-module(ssl_observer).


%% API
-export([add_callback_module/1]).

-callback handshake_finished(Reason :: ok | {integer(), closed} | {integer(), {tls_alert, string()}},
    Version :: atom(),
    Ciphers :: [ssl:erl_cipher_suite()]) ->
    no_return().

-callback handshake_started(Version :: atom()) -> no_return().

-spec add_callback_module(module()) -> ok.
add_callback_module(Module) ->
    ssl_tracer:add_callback_module(Module).
