%%%-------------------------------------------------------------------
%% @doc personal_mtproxy supervisor
%% @end
%%%-------------------------------------------------------------------

-module(personal_mtproxy_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 3, period => 60},
    ChildSpecs = [
        #{id => pm_registry,
          start => {pm_registry, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [pm_registry]}
    ],
    {ok, {SupFlags, ChildSpecs}}.
