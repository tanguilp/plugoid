defmodule Plugoid.Logout.FrontChannel do
  @moduledoc false

  @behaviour Plug

  alias Plugoid.Session.AuthSession

  def init(opts), do: opts

  def call(%Plug.Conn{query_params: %{"iss" => issuer, "sid" => sid}} = conn, _opts) do
    case AuthSession.info(conn, issuer) do
      %AuthSession.Info{sid: ^sid} ->
        AuthSession.set_unauthenticated(conn, issuer)

      _ ->
        conn
    end
    |> Plug.Conn.put_resp_header("cache-control", "no-cache, no-store")
    |> Plug.Conn.put_resp_header("pragma", "no-cache")
    |> Plug.Conn.resp(200, "")
  end

  def call(%Plug.Conn{query_params: %{"iss" => _}} = conn, _opts) do
    Plug.Conn.resp(conn, 400, "missing sid parameter")
  end

  def call(%Plug.Conn{query_params: %{"sid" => _}} = conn, _opts) do
    Plug.Conn.resp(conn, 400, "missing iss parameter")
  end

  def call(
    %Plug.Conn{private: %{frontchannel_logout_session_required: false}} = conn,
    _opts
  ) do
    conn
    |> AuthSession.destroy()
    |> Plug.Conn.put_resp_header("cache-control", "no-cache, no-store")
    |> Plug.Conn.put_resp_header("pragma", "no-cache")
    |> Plug.Conn.resp(200, "")
  end

  def call(conn, _opts) do
    Plug.Conn.resp(conn, 403, "session required")
  end
end
