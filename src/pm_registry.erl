%%%-------------------------------------------------------------------
%% @doc Personal domain registry: DETS persistence + registration
%% @end
%%%-------------------------------------------------------------------

-module(pm_registry).

-behaviour(gen_server).

-export([start_link/0, register/1, revoke/1, list/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).
-define(APP, personal_mtproxy).
-define(DETS_TABLE, pm_subdomains).

-record(state, {dets_ref}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register(UserId) ->
    gen_server:call(?SERVER, {register, UserId}).

revoke(Subdomain) ->
    gen_server:call(?SERVER, {revoke, Subdomain}).

list() ->
    gen_server:call(?SERVER, list).

init([]) ->
    {ok, DetsFile} = application:get_env(?APP, dets_file),

    % Open or create DETS
    {ok, DetsRef} = dets:open_file(?DETS_TABLE, [{file, DetsFile}, {keypos, 1}]),

    ReplayState = dets:foldl(fun collect_replay_entry/2, empty_replay_state(), DetsRef),
    ok = maybe_normalize_dets(DetsRef, ReplayState),
    ok = replay_active_subdomains(ReplayState),
    log_replay_summary(ReplayState),

    {ok, #state{dets_ref = DetsRef}}.

handle_call({register, UserId}, _From, State = #state{dets_ref = DetsRef}) ->
    % Generate 5-char random hex slug with collision retry (max 5 attempts)
    case generate_slug(DetsRef, 5) of
        {error, Reason} ->
            {reply, {error, Reason}, State};
        Subdomain ->
            {ok, [#{port := Port, secret := BaseSecret} | _]} = application:get_env(mtproto_proxy, ports),
            % Store in DETS
            ok = dets:insert(DetsRef, {Subdomain, UserId, erlang:system_time(second)}),
            % Add to live policy table
            ok = mtp_policy_table:add(personal_domains, tls_domain, Subdomain),
            {reply, {ok, Subdomain, Port, BaseSecret}, State}
    end;

handle_call({revoke, Subdomain}, _From, State = #state{dets_ref = DetsRef}) ->
    case dets:lookup(DetsRef, Subdomain) of
        [] ->
            {reply, {error, not_found}, State};
        _ ->
            ok = dets:delete(DetsRef, Subdomain),
            ok = mtp_policy_table:del(personal_domains, tls_domain, Subdomain),
            {reply, ok, State}
    end;

handle_call(list, _From, State = #state{dets_ref = DetsRef}) ->
    Entries = lists:reverse(dets:foldl(fun collect_list_entry/2, [], DetsRef)),
    {reply, Entries, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{dets_ref = DetsRef}) ->
    ok = dets:close(DetsRef),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Private helpers

generate_slug(DetsRef, Retries) ->
    case Retries of
        0 ->
            {error, max_retries};
        _ ->
            Slug = [($a + rand:uniform(26) - 1) || _ <- lists:seq(1, 5)],
            {ok, BaseDomain} = application:get_env(?APP, base_domain),
            Subdomain = list_to_binary(Slug ++ "." ++ BaseDomain),

            case dets:lookup(DetsRef, Subdomain) of
                [] ->
                    Subdomain;
                _ ->
                    % Collision, retry
                    generate_slug(DetsRef, Retries - 1)
            end
    end.

empty_replay_state() ->
    #{active => [],
      converted => [],
      revoked => [],
      unknown => []}.

collect_replay_entry({_Subdomain, _UserId, _Timestamp} = Entry, State) ->
    State#{active := [Entry | maps:get(active, State)]};
collect_replay_entry({Subdomain, UserId, Timestamp, undefined}, State) ->
    ConvertedEntry = {Subdomain, UserId, Timestamp},
    State#{
      active := [ConvertedEntry | maps:get(active, State)],
      converted := [ConvertedEntry | maps:get(converted, State)]
    };
collect_replay_entry({Subdomain, _UserId, _Timestamp, RevokedAt}, State) when is_integer(RevokedAt) ->
    State#{revoked := [Subdomain | maps:get(revoked, State)]};
collect_replay_entry(Entry, State) ->
    State#{unknown := [Entry | maps:get(unknown, State)]}.

collect_list_entry({_, _, _} = Entry, Acc) ->
    [Entry | Acc];
collect_list_entry({Subdomain, UserId, Timestamp, undefined}, Acc) ->
    [{Subdomain, UserId, Timestamp} | Acc];
collect_list_entry({_Subdomain, _UserId, _Timestamp, RevokedAt}, Acc) when is_integer(RevokedAt) ->
    Acc;
collect_list_entry(_Entry, Acc) ->
    Acc.

maybe_normalize_dets(DetsRef, ReplayState) ->
    ConvertedEntries = maps:get(converted, ReplayState),
    RevokedSubdomains = maps:get(revoked, ReplayState),
    ok = lists:foreach(fun(Entry) -> ok = dets:insert(DetsRef, Entry) end, ConvertedEntries),
    ok = lists:foreach(fun(Subdomain) -> ok = dets:delete(DetsRef, Subdomain) end, RevokedSubdomains).

replay_active_subdomains(ReplayState) ->
    lists:foreach(
      fun({Subdomain, _UserId, _Timestamp}) ->
              ok = mtp_policy_table:add(personal_domains, tls_domain, Subdomain)
      end,
      maps:get(active, ReplayState)).

log_replay_summary(ReplayState) ->
    Converted = length(maps:get(converted, ReplayState)),
    Revoked = length(maps:get(revoked, ReplayState)),
    Unknown = maps:get(unknown, ReplayState),
    case {Converted, Revoked, Unknown} of
        {0, 0, []} ->
            ok;
        _ ->
            ?LOG_WARNING(
               "Normalized DETS registry entries converted=~p revoked_removed=~p unknown=~p",
               [Converted, Revoked, Unknown])
    end.
