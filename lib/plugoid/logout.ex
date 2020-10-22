defmodule Plugoid.Logout do
  @moduledoc """
  Plug supporting OpenID Connect Logout

  This plug supports the following specifications:
  - [OpenID Connect Session Management 1.0 - draft 30](https://openid.net/specs/openid-connect-session-1_0-30.html)

  ## Automatic configuration in a router

      defmodule Myapp.Router do
        use Plugoid.Logout
      end

  installs a route to `/openid_connect_logout` in a Phoenix router.

  ## Options

  - `:path`: the path of the redirect URI. Defaults to `"openid_connect_logout"`
  """

  defmacro __using__(opts) do
    quote do
      pipeline :oidc_logout_pipeline do
        plug :accepts, ["html"]
        plug :fetch_query_params
      end

      scope unquote(opts[:path]) || "/openid_connect_logout", Plugoid.Logout do
        pipe_through :oidc_logout_pipeline

        get "/check_session", SessionManagement, :call,
          as: :openid_connect_logout_check_session
      end
    end
  end

  @doc """
  Returns the session management iframe path, or `nil` if the logout API is not set up
  """
  @spec check_session_path(Plug.Conn.t()) :: String.t() | nil
  def check_session_path(%Plug.Conn{} = conn) do
    router = Phoenix.Controller.router_module(conn)

    apply(
      Module.concat(router, Helpers),
      :openid_connect_logout_check_session_path,
      [Phoenix.Controller.endpoint_module(conn), :call]
    )
  rescue
    _ ->
      nil
  end
end
