defmodule Plugoid.Logout do
  defmacro __using__(_opts) do
    quote do
      pipeline :oidc_logout_pipeline do
        plug :accepts, ["html"]
        plug :fetch_query_params
      end

      scope "/openid_connect_logout_api/:issuer/", Plugoid.Logout do
        pipe_through :oidc_logout_pipeline

        get "/check_session", SessionManagement, :call,
          as: :openid_connect_logout_api
      end
    end
  end

  @doc """
  Returns the path to the logout management API or `nil` if it was not set up

  The issuer is used as a component of the path, for instance:
  `"/openid_connect_logout_api/<ISSUER>/"`.
  """
  @spec api_path(Plug.Conn.t(), Plugoid.opts()) :: String.t() | nil
  def api_path(%Plug.Conn{} = conn, opts) do
    router = Phoenix.Controller.router_module(conn)

    apply(
      Module.concat(router, Helpers),
      :openid_connect_logout_api_path,
      [Phoenix.Controller.endpoint_module(conn), :call, opts[:issuer]]
    )
  rescue
    _ ->
      nil
  end

  @doc """
  Returns the session management iframe path, or `nil` if the logout API is not set up

  Example: `"/openid_connect_logout_api/<ISSUER>/check_session"`.
  """
  @spec session_management_iframe_path(Plug.Conn.t(), Plugoid.opts()) :: String.t() | nil
  def session_management_iframe_path(%Plug.Conn{} = conn, opts) do
    case api_path(conn, opts) do
      <<_::binary>> = api_path ->
        api_path <> "check_session"

      nil ->
        nil
    end
  end
end
