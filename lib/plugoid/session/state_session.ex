defmodule Plugoid.Session.StateSession do
  @moduledoc false

  alias OIDC.Auth.Challenge
  alias Plugoid.OIDCRequest

  @type redirect_token :: String.t()

  defmodule CookieNotFoundError do
    defexception message: "state cookie was not found"
  end

  @spec store_oidc_request(Plug.Conn.t(), OIDCRequest.t(), non_neg_integer()) :: Plug.Conn.t()
  def store_oidc_request(conn, oidc_request, max_concurrent_state_session) do
    {base_cookie_name, cookie_opts, cookie_store, cookie_store_opts} = cookie_config()

    cookie_name = gen_cookie_name(conn, base_cookie_name)

    conn = Plug.Conn.fetch_cookies(conn)

    # deleting excess cookies in regards to max_concurrent_state_session
    conn =
      Enum.map(conn.req_cookies, fn {cookie_name, _} -> cookie_name end)
      |> Enum.filter(fn cookie_name -> String.starts_with?(cookie_name, base_cookie_name) end)
      |> Enum.map(fn cookie_name -> String.trim_leading(cookie_name, base_cookie_name <> "_") end)
      |> Enum.sort_by(fn cookie_number -> String.to_integer(cookie_number) end)
      |> Enum.split(1 - max_concurrent_state_session)
      |> elem(0)
      |> Enum.reduce(conn, fn cookie_number, acc ->
        cookie_name = base_cookie_name <> "_" <> cookie_number

        cookie_store.delete(acc, cookie_name, cookie_store_opts)

        Plug.Conn.delete_resp_cookie(acc, base_cookie_name <> "_" <> cookie_number)
      end)

    sid = cookie_store.put(conn, nil, oidc_request, cookie_store_opts)

    Plug.Conn.put_resp_cookie(conn, cookie_name, sid, cookie_opts)
  end

  @spec get_and_delete_oidc_request(
          Plug.Conn.t(),
          state :: String.t()
        ) :: {:ok, {Plug.Conn.t(), OIDCRequest.t()}} | {:error, atom()}
  def get_and_delete_oidc_request(conn, state) do
    {base_cookie_name, cookie_opts, cookie_store, cookie_store_opts} = cookie_config()

    conn = Plug.Conn.fetch_cookies(conn)

    Enum.find_value(
      conn.req_cookies,
      {:error, %CookieNotFoundError{}},
      fn {cookie_name, _cookie_value} ->
        if String.starts_with?(cookie_name, base_cookie_name <> "_") do
          sid = conn.req_cookies[cookie_name]

          case cookie_store.get(conn, sid, cookie_store_opts) do
            {sid, %OIDCRequest{challenge: %Challenge{state_param: ^state}} = oidc_request} ->
              {:ok, {sid, cookie_name, oidc_request}}

            _ ->
              nil
          end
        end
      end
    )
    |> case do
      {:ok, {sid, cookie_name, oidc_request}} ->
        cookie_store.delete(conn, sid, cookie_store_opts)

        conn = Plug.Conn.delete_resp_cookie(conn, cookie_name, cookie_opts)

        {:ok, {conn, oidc_request}}

      {:error, _} = error ->
        error
    end
  end

  @spec gen_cookie_name(Plug.Conn.t(), String.t()) :: String.t()
  defp gen_cookie_name(conn, base_cookie_name) do
    current_num =
      Enum.reduce(
        conn.req_cookies,
        0,
        fn {cookie_name, _cookie_value}, acc ->
          if String.starts_with?(cookie_name, base_cookie_name <> "_") do
            cookie_name
            |> String.trim_leading(base_cookie_name <> "_")
            |> Integer.parse()
            |> case do
              {num, _} when is_integer(num) and num > acc ->
                num

              _ ->
                acc
            end
          else
            acc
          end
        end
      )

    base_cookie_name <> "_" <> to_string(current_num + 1)
  end

  defp cookie_config() do
    name = Application.get_env(:plugoid, :state_cookie_name, "plugoid_state")
    opts = Application.get_env(:plugoid, :state_cookie_opts, secure: true, extra: "SameSite=None")

    store =
      Application.get_env(:plugoid, :state_cookie_store, :cookie) |> Plug.Session.Store.get()

    store_opts = Application.get_env(:plugoid, :state_cookie_store_opts, []) |> store.init()

    {name, opts, store, store_opts}
  end
end
