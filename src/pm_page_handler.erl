%%%-------------------------------------------------------------------
%% @doc Cowboy handler for protected HTML pages.
%% @end
%%%-------------------------------------------------------------------

-module(pm_page_handler).

-export([init/2]).

init(Req0 = #{path := Path}, State) ->
    case pm_auth:ensure_authorized(Req0) of
        {ok, Req1} ->
            Req2 =
                case Path of
                    <<"/">> ->
                        cowboy_req:reply(302, #{<<"location">> => <<"/admin.html">>}, Req1);
                    <<"/admin.html">> ->
                        serve_file("htdocs/admin.html", <<"text/html; charset=utf-8">>, Req1)
                end,
            {ok, Req2, State};
        {stop, Reply} ->
            {ok, Reply, State}
    end.

serve_file(RelPath, ContentType, Req) ->
    PrivDir = code:priv_dir(personal_mtproxy),
    FullPath = filename:join(PrivDir, RelPath),
    case file:read_file(FullPath) of
        {ok, Body} ->
            cowboy_req:reply(200, no_cache_headers(#{<<"content-type">> => ContentType}), Body, Req);
        {error, enoent} ->
            cowboy_req:reply(404, #{<<"content-type">> => <<"text/plain; charset=utf-8">>},
                             <<"Not found">>, Req)
    end.

no_cache_headers(Headers) ->
    Headers#{
      <<"cache-control">> => <<"no-store, no-cache, must-revalidate, max-age=0">>,
      <<"pragma">> => <<"no-cache">>,
      <<"expires">> => <<"0">>,
      <<"vary">> => <<"authorization">>
     }.
