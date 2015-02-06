%%%-------------------------------------------------------------------
%% @doc ssl_observer top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(ssl_observer_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).


%%====================================================================
%% API functions
%%====================================================================

-spec start_link() -> {ok, pid()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
-spec init([]) -> {ok, {{one_for_all, non_neg_integer(), non_neg_integer()},
                        [supervisor:child_spec()]}}.
init([]) ->
    {ok, { {one_for_all, 1, 1}, [?CHILD(ssl_tracer, worker)]} }.

%%====================================================================
%% Internal functions
%%====================================================================
