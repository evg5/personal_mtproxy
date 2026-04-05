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

register(Email) ->
    gen_server:call(?SERVER, {register, Email}).

revoke(Subdomain) ->
    gen_server:call(?SERVER, {revoke, Subdomain}).

list() ->
    gen_server:call(?SERVER, list).

init([]) ->
    {ok, DetsFile} = application:get_env(?APP, dets_file),

    % Open or create DETS
    {ok, DetsRef} = dets:open_file(?DETS_TABLE, [{file, DetsFile}, {keypos, 1}]),

    % Replay all stored subdomains into policy table
    ok = dets:foldl(
      fun({Subdomain, _Email, _Timestamp}, ok) ->
              mtp_policy_table:add(personal_domains, tls_domain, Subdomain)
      end,
      ok, DetsRef),

    {ok, #state{dets_ref = DetsRef}}.

handle_call({register, Email}, _From, State = #state{dets_ref = DetsRef}) ->
    % Generate 5-char random hex slug with collision retry (max 5 attempts)
    case generate_slug(DetsRef, 5) of
        {error, Reason} ->
            {reply, {error, Reason}, State};
        Subdomain ->
            {ok, [#{port := Port, secret := BaseSecret} | _]} = application:get_env(mtproto_proxy, ports),
            % Store in DETS
            ok = dets:insert(DetsRef, {Subdomain, Email, erlang:system_time(second)}),
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
    Entries = dets:match_object(DetsRef, {'_', '_', '_'}),
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
