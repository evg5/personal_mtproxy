%%%-------------------------------------------------------------------
%% @doc Minimal hardcoded HTTP Basic Auth helper.
%% @end
%%%-------------------------------------------------------------------

-module(pm_auth).

-export([ensure_authorized/1]).

-define(REALM, <<"Restricted">>).

ensure_authorized(Req) ->
    case cowboy_req:header(<<"authorization">>, Req) of
        undefined ->
            unauthorized(Req);
        AuthHeader ->
            case AuthHeader =:= expected_auth_header() of
                true ->
                    {ok, Req};
                false ->
                    unauthorized(Req)
            end
    end.

expected_auth_header() ->
    Username = application:get_env(personal_mtproxy, admin_username, <<"admin">>),
    Password = application:get_env(personal_mtproxy, admin_password, <<"change-me">>),
    Encoded = base64:encode(iolist_to_binary([Username, <<":">>, Password])),
    iolist_to_binary([<<"Basic ">>, Encoded]).

unauthorized(Req) ->
    Headers = #{
        <<"content-type">> => <<"text/plain; charset=utf-8">>,
        <<"www-authenticate">> => iolist_to_binary([<<"Basic realm=\"">>, ?REALM, <<"\"">>])
    },
    Reply = cowboy_req:reply(401, Headers, <<"Unauthorized">>, Req),
    {stop, Reply}.
