defmodule Plugoid.Session.AuthSession do
  @moduledoc false

  alias OIDC.Auth.OPResponseSuccess

  defmodule Info do
    @moduledoc false

    @enforce_keys [:claims, :auth_time_monotonic]

    defstruct [:claims, :auth_time_monotonic]

    @type t :: %__MODULE__{
      claims: %{String.t() => String.t()},
      auth_time_monotonic: integer()
    }
  end

  @doc false
  @spec set_authenticated(
    Plug.Conn.t(),
    issuer :: String.t(),
    OPResponseSuccess.t()
  ) :: Plug.Conn.t()
  def set_authenticated(conn, issuer, op_response) do
    {cookie_name, cookie_opts, cookie_store, cookie_store_opts} = cookie_config()

    claims_keys = Application.get_env(:plugoid, :claims, ["sub", "acr"])
    claims = Map.take(op_response.id_token_claims, claims_keys)

    session_info = %Info{
      claims: claims,
      auth_time_monotonic: System.monotonic_time(:second)
    }

    conn = Plug.Conn.fetch_cookies(conn)

    sid = conn.req_cookies[cookie_name]

    session_data =
      case sid do
        nil ->
          Map.put(%{}, issuer, session_info)

        sid ->
          case cookie_store.get(conn, sid, cookie_store_opts) do
            {nil, _} ->
              Map.put(%{}, issuer, session_info)

            {_, session_data} ->
              Map.put(session_data, issuer, session_info)
          end
      end

    sid = cookie_store.put(conn, sid, session_data, cookie_store_opts)

    Plug.Conn.put_resp_cookie(conn, cookie_name, sid, cookie_opts)
  end

  @spec set_unauthenticated(Plug.Conn.t(), OIDC.issuer()) :: Plug.Conn.t()
  def set_unauthenticated(conn, issuer) do
    {cookie_name, cookie_opts, cookie_store, cookie_store_opts} = cookie_config()

    conn = Plug.Conn.fetch_cookies(conn)

    sid = conn.req_cookies[cookie_name]

    case sid do
      nil ->
        conn

      sid ->
        case cookie_store.get(conn, sid, cookie_store_opts) do
          {nil, _} ->
            conn

          {_, session_data} ->
            session_data = Map.delete(session_data, issuer)

            sid = cookie_store.put(conn, sid, session_data, cookie_store_opts)

            Plug.Conn.put_resp_cookie(conn, cookie_name, sid, cookie_opts)
        end
    end
  end

  @spec destroy(Plug.Conn.t()) :: Plug.Conn.t()
  def destroy(conn) do
    {cookie_name, cookie_opts, cookie_store, cookie_store_opts} = cookie_config()

    conn = Plug.Conn.fetch_cookies(conn)

    sid = conn.req_cookies[cookie_name]

    case sid do
      nil ->
        conn

      sid ->
        case cookie_store.get(conn, sid, cookie_store_opts) do
          {nil, _} ->
            Plug.Conn.delete_resp_cookie(conn, cookie_name, cookie_opts)

          {_, _session_data} ->
            cookie_store.delete(conn, sid, cookie_store_opts)

            Plug.Conn.delete_resp_cookie(conn, cookie_name, cookie_opts)
        end
    end
  end

  @spec info(Plug.Conn.t(), issuer :: String.t()) :: %Info{} | nil
  def info(conn, issuer) do
    {cookie_name, _cookie_opts, cookie_store, cookie_store_opts} = cookie_config()

    conn = Plug.Conn.fetch_cookies(conn)

    sid = conn.req_cookies[cookie_name]

    case sid do
      nil ->
        nil

      sid ->
        case cookie_store.get(conn, sid, cookie_store_opts) do
          {nil, _} ->
            nil

          {_, session_data} ->
            session_data[issuer]
        end
    end
  end

  defp cookie_config() do
    name = Application.get_env(:plugoid, :auth_cookie_name, "plugoid_auth")
    opts = Application.get_env(:plugoid, :auth_cookie_opts, [extra: "SameSite=Lax"])
    store =
      Application.get_env(:plugoid, :auth_cookie_store, :ets) |> Plug.Session.Store.get()
    store_opts =
      Application.get_env(:plugoid, :auth_cookie_store_opts, [table: :plugoid_auth_cookie])
      |> store.init()

    {name, opts, store, store_opts}
  end
end
