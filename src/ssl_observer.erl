%%%-------------------------------------------------------------------
%% @doc ssl_observer public API
%% @end
%%%-------------------------------------------------------------------

-module(ssl_observer).

%% API
-export([add_callback_module/1]).

-callback handshake_finished(Reason :: ok | closed | {tls_alert, string()},
    Version :: string(),
    Ciphers :: [ssl:erl_cipher_suite()]) ->
    no_return().

-spec add_callback_module(module()) -> ok.
add_callback_module(Module) ->
    ssl_tracer:add_callback_module(Module).
