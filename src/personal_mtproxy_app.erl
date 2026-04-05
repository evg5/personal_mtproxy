%%%-------------------------------------------------------------------
%% @doc personal_mtproxy application start handler
%% @end
%%%-------------------------------------------------------------------

-module(personal_mtproxy_app).

-behaviour(application).

-export([start/2, stop/1]).

-include_lib("kernel/include/logger.hrl").

-define(APP, personal_mtproxy).

start(_StartType, _StartArgs) ->
    % Validate mtproto_proxy port config
    case validate_mtproto_ports() of
        ok ->
            % Start supervisor
            Res = {ok, _} = personal_mtproxy_sup:start_link(),

            % Determine Cowboy bind address: explicit listen_ip/listen_port
            % in personal_mtproxy config take priority; fall back to domain_fronting.
            {CowboyIp, CowboyPort} = cowboy_listen_addr(),

            {ok, BaseDomain} = application:get_env(?APP, base_domain),
            {ok, SslCert} = application:get_env(?APP, ssl_cert),
            {ok, SslKey} = application:get_env(?APP, ssl_key),

            % Ensure DETS dir exists
            {ok, DetsFile} = application:get_env(?APP, dets_file),
            ok = filelib:ensure_dir(DetsFile),
            
            cowboy:start_tls(
              https_listener,
              [{port, CowboyPort}, {ip, CowboyIp},
               {certfile, SslCert}, {keyfile, SslKey}],
              #{env => #{dispatch => routes()}}
            ),

            ?LOG_INFO("Personal MTProto Proxy UI on https://~s:~p", [BaseDomain, CowboyPort]),
            
            Res;
        {error, Reason} ->
            ?LOG_ERROR("mtproto_proxy port validation failed: ~p", [Reason]),
            {error, Reason}
    end.

stop(_State) ->
    ok.

%% Validate that IPv4 and IPv6 listeners agree on port and secret
validate_mtproto_ports() ->
    case application:get_env(mtproto_proxy, ports) of
        undefined ->
            {error, no_ports_configured};
        {ok, []} ->
            {error, no_ports_configured};
        {ok, [#{port := Port, secret := Secret} | Rest]} ->
            case lists:all(
              fun(#{port := P, secret := S}) ->
                      P == Port andalso S == Secret
              end,
              Rest)
            of
                true ->
                    ok;
                false ->
                    {error, {mismatched_ports, [#{port => Port, secret => Secret} | Rest]}}
            end;
        _ ->
            {error, invalid_port_config}
    end.

parse_host_port(HostPort) ->
    case string:split(HostPort, ":") of
        [Host, PortStr] ->
            {ok, Ip} = inet:parse_address(Host),
            {Ip, list_to_integer(PortStr)};
        _ ->
            error({badarg, invalid_domain_fronting_config, HostPort})
    end.

cowboy_listen_addr() ->
    case {application:get_env(?APP, web_listen_ip), application:get_env(?APP, web_listen_port)} of
        {{ok, Ip}, {ok, Port}} ->
            {ok, ParsedIp} = inet:parse_address(Ip),
            {ParsedIp, Port};
        _ ->
            {ok, DomainFronting} = application:get_env(mtproto_proxy, domain_fronting),
            parse_host_port(DomainFronting)
    end.

routes() ->
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/api/proxies", pm_web_handler, []},
            {"/", cowboy_static, {priv_file, personal_mtproxy, "htdocs/index.html"}},
            {"/admin.html", cowboy_static, {priv_file, personal_mtproxy, "htdocs/admin.html"}},
            {"/static/[...]", cowboy_static, {priv_dir, personal_mtproxy, "htdocs"}}
        ]}
    ]),
    Dispatch.
