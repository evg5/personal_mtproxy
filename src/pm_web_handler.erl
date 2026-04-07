%%%-------------------------------------------------------------------
%% @doc Cowboy handler for JSON API endpoints
%% POST   /api/proxies                  → register new proxy, return JSON
%% DELETE /api/proxies?subdomain=<sub>  → revoke proxy
%% @end
%%%-------------------------------------------------------------------

-module(pm_web_handler).

-export([init/2]).

-include_lib("kernel/include/logger.hrl").

init(Req, State) ->
    case pm_auth:ensure_authorized(Req) of
        {ok, Req1} ->
            {Code, Body, Req2} = handle(Req1),
            Reply = cowboy_req:reply(Code, #{<<"content-type">> => <<"application/json">>}, jsx:encode(Body), Req2),
            {ok, Reply, State};
        {stop, Reply} ->
            {ok, Reply, State}
    end.

handle(Req = #{method := <<"POST">>, path := <<"/api/proxies">>}) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    Params = uri_string:dissect_query(Body),
    UserId = case proplists:get_value(<<"user_id">>, Params) of
                 undefined -> proplists:get_value(<<"email">>, Params, <<>>);
                 Value -> Value
             end,
    case pm_registry:register(UserId) of
        {ok, Subdomain, Port, BaseSecret} ->
            {ok, BaseDomain} = application:get_env(personal_mtproxy, base_domain),
            Secret = iolist_to_binary([<<"ee">>,
                                       string:lowercase(BaseSecret),
                                       string:lowercase(binary:encode_hex(Subdomain))]),
            Query = uri_string:compose_query([
              {<<"server">>, list_to_binary(BaseDomain)},
              {<<"port">>,   integer_to_binary(Port)},
              {<<"secret">>, Secret}
            ]),
            TmeLink = iolist_to_binary(uri_string:recompose(
              #{scheme => <<"https">>, host => <<"t.me">>, path => <<"/proxy">>, query => Query})),
            TgLink = iolist_to_binary(uri_string:recompose(
              #{scheme => <<"tg">>, host => <<"proxy">>, path => <<>>, query => Query})),
            {200, #{subdomain => Subdomain, link => TmeLink, tg_link => TgLink}, Req1};
        {error, Reason} ->
            ErrMsg = iolist_to_binary(io_lib:format("~p", [Reason])),
            {500, #{error => ErrMsg}, Req1}
    end;

handle(Req = #{method := <<"DELETE">>, path := <<"/api/proxies">>}) ->
    Params = cowboy_req:parse_qs(Req),
    case proplists:get_value(<<"subdomain">>, Params) of
        undefined ->
            {400, #{error => <<"missing subdomain parameter">>}, Req};
        Subdomain ->
            case pm_registry:revoke(Subdomain) of
                ok ->
                    {200, #{ok => true}, Req};
                {error, not_found} ->
                    {404, #{error => <<"subdomain not found">>}, Req}
            end
    end;

handle(Req) ->
    {404, #{error => <<"not found">>}, Req}.
