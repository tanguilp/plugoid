defmodule Plugoid.Logout do
  @moduledoc """
  User logout functions and plugs

  In OpenID Connect, logout consists in 2 things:
  - redirecting to the OP to log out the user. This is called RP-initiated logout.
  Typically, when clicking on a link on the current site, the user is redirected
  to the OP for deconnection
  - on the OP, logging out the user from all the site where the user is logged in.
  This problem is surprisingly hard to solve, and 3 standards have been developped:
    - Session Management: from an hidden iframe, the site regularly pings the OP
    to know about the authenticated session status
    - Frontchannel logout: when disconnecting on the OP, hidden iframes are opened
    to a specific logout URI on the sites where the user has sessions, ordering them
    to terminate
    - Backchannel logout: when disconnecting on the OP, the OP sends HTTP requests
    to a specific endpoint of sites where the user is logged in

  Plugoid implements RP-initiated logout (see
  [Logout functions](#module-logout-functions)) and frontchannel logout (see
  [Installing the logout Plug](#module-installing-the-logout-plug)).

  Session Management is unsupported due to its complexity, and backchannel logout
  is unsupported because it requires stateful session backend (possibly with some
  indexing capabilities) and therefore `Plug.Session.COOKIE` could not be
  supported. This may change in the future.

  ## Installing the logout Plug

      defmodule Myapp.Router do
        use Plugoid.Logout
      end

  installs a route to `/openid_connect_logout` in a Phoenix router.

  ### Options
  - `:path`: the path of the redirect URI. Defaults to `"openid_connect_logout"`
  - `:frontchannel_logout_session_required`: a boolean indicating if the OP has to
  provide the issuer and session ID when logging out using frontchannel logout. Defaults
  to `true`

  ## Determining client metadata

  When using this module, Plugoid automatically installs functions into the router for
  the following client metadata:

  - `"frontchannel_logout_uri"`:

        iex> MyAppWeb.Router.plugoid_frontchannel_logout_uri()
        "http://localhost:4000/openid_connect_logout/front_channel"

  - `":frontchannel_logout_session_required"`:

        iex> MyAppWeb.Router.plugoid_frontchannel_logout_session_required()
        true
  """

  @default_logout_opts [id_token_callback: &__MODULE__.id_token_callback/2]

  require Logger

  alias Plugoid.{Session.AuthSession, Utils}

  @typedoc """
  Logout options

  ### RP-initiated logout options
  - `:id_token_callback`: a function that retrieves an ID token, possibly expired, for a given
  user. When not set, `Plugoid` tries to use the `OAuth2TokenManager` library if installed.
  - `:post_logout_redirect_uri`: the URI to redirect to after logout. Note that it can be
  configured at the client level (using the `"post_logout_redirect_uris"` metadata field).
  - `:state`: a string that will be passed back to the post logout URI when RP-initiated logout
  is used
  """
  @type logout_opts :: [logout_opt()]
  @type logout_opt ::
  {:id_token_callback, (OIDC.issuer(), OIDC.subject() -> OIDC.IDToken.serialized() | nil)}
  | {:post_logout_redirect_uri, String.t()}
  | {:state, String.t()}

  defmodule UnsupportedError do
    @moduledoc """
    RP-initiated logout is not supported by the OP
    """

    defexception message: "RP-initiated logout is not supported by the OP"
  end

  defmodule UnauthenticatedConnectionError do
    @moduledoc """
    The current `t:Plug.Conn.t/0` is not authenticated by Plugoid
    """

    defexception message: "the current connection is not authenticated"
  end

  defmacro __using__(opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:path, "/openid_connect_logout")
      |> Keyword.put_new(:frontchannel_logout_session_required, true)

    quote do
      def plugoid_frontchannel_logout_uri(endpoint \\ nil) do
        endpoint =
          if endpoint do
            endpoint
          else
            Module.split(__MODULE__)
            |> List.pop_at(-1)
            |> elem(1)
            |> Kernel.++([Endpoint])
            |> Module.safe_concat()
          end

        apply(
          Module.concat(__MODULE__, Helpers),
          :openid_connect_logout_frontchannel_url,
          [endpoint, :call]
        )
      end

      def plugoid_frontchannel_logout_session_required(),
        do: unquote(opts)[:frontchannel_logout_session_required]

      pipeline :oidc_logout_pipeline do
        plug :accepts, ["html"]
        plug :fetch_query_params
      end

      scope unquote(opts)[:path], Plugoid.Logout do
        pipe_through :oidc_logout_pipeline

        get "/front_channel", FrontChannel, :call,
          as: :openid_connect_logout_frontchannel,
          private:
            unquote(opts)
            |> Keyword.take([:frontchannel_logout_session_required])
            |> Enum.into(%{})
      end
    end
  end

  @doc """
  Logs out a user, possibly from the OP when supported by it

  When using this function, the user is logged out locally (the authentication session for the
  current OP is deleted) and then redirected to the OP for log out if RP-initiated logout is
  supported by it.

  At the end of the process, the user is redirected back to the post logout redirection URI,
  configured either in the client configuration (`"post_logout_redirect_uris"`, the first URI
  is chosen by default) or by the `:post_logout_redirect_uri` option.

  If none are configured, the user is redirected to `"/"`.

  The connection **must** be authenticated by Plugoid, otherwise a
  `Plugoid.Logout.UnauthenticatedConnectionError` exception is raised.
  """
  @spec logout(Plug.Conn.t(), logout_opts) :: Plug.Conn.t()
  def logout(conn, logout_opts \\ @default_logout_opts) do
    rp_initiated_logout(conn, logout_opts)
  rescue
    __MODULE__.UnsupportedError ->
      case post_logout_redirect_uri(conn, logout_opts) do
        <<_::binary>> = post_logout_redirect_uri ->
          conn
          |> local_logout()
          |> Phoenix.Controller.redirect(external: post_logout_redirect_uri)
          |> Plug.Conn.halt()

        nil ->
          conn
          |> local_logout()
          |> Phoenix.Controller.redirect(to: "/")
          |> Plug.Conn.halt()
      end
  end

  @doc """
  Locally destroys the authentication session at an OP

  The user is not logged out from the OP or redirected to it. As a consequence, any further
  access to a protected page may silently re-authenticate the user, if the authentication
  user session is still active at the OP.

  It is recommended to redirect to a non-protected page after using this function. Otherwise,
  the user will be redirected for authentication to the OP.
  """
  @spec local_logout(Plug.Conn.t(), OIDC.issuer()) :: Plug.Conn.t()
  def local_logout(%Plug.Conn{} = conn, <<_::binary>> = issuer) do
    case AuthSession.info(conn, issuer) do
      %AuthSession.Info{} = auth_session_info ->
        conn = AuthSession.set_unauthenticated(conn, issuer)

        Logger.info(%{
          what: :plugoid_user_logout,
          result: :ok,
          details: %{
            logout_type: :local,
            iss: issuer,
            sid: auth_session_info.sid,
            sub: auth_session_info.sub
          }
        })

        conn

      _ ->
        conn
    end
  end

  @doc """
  Locally destroys the current authentication session

  Same as `local_logout/2`, except the OP to disconnect from is determined by the
  current connection (`t:Plug.Conn.t/0`), which means the current connection must be
  authenticated by `Plugoid`.

  If the current connection is not authenticated, then this function raises a
  `Plugoid.Logout.UnauthenticatedConnectionError` exception. To verify if the
  connection is authenticated, see `Plugoid.authenticated?/1`.
  """
  @spec local_logout(Plug.Conn.t()) :: Plug.Conn.t()
  def local_logout(%Plug.Conn{private: %{plugoid_authenticated: true}} = conn),
    do: local_logout(conn, conn.private.plugoid_opts[:issuer])
  def local_logout(_),
    do: raise UnauthenticatedConnectionError

  @doc """
  Logs out a user from all OPs

  The Plugoid authentication cookie is unset.
  """
  @spec local_logout_all(Plug.Conn.t()) :: Plug.Conn.t()
  def local_logout_all(%Plug.Conn{} = conn) do
    conn = AuthSession.destroy(conn)

    Logger.info(%{
      what: :plugoid_user_logout,
      result: :ok,
      details: %{logout_type: :local_all}
    })

    conn
  end

  @doc """
  Performs an RP-initiated logout at the current OP

  The connection **must** be authenticated with `Plugoid`, otherwise an
  `Plugoid.Logout.UnauthenticatedConnectionError` exception is raised.

  If the OP does not support logout, an `Plugoid.Logout.UnsupportedError` exception is raised.
  """
  @spec rp_initiated_logout(Plug.Conn.t(), logout_opts()) :: Plug.Conn.t()
  def rp_initiated_logout(conn, logout_opts \\ @default_logout_opts)

  def rp_initiated_logout(
    %Plug.Conn{private: %{plugoid_authenticated: true}} = conn,
    logout_opts
  ) do
    case Utils.server_metadata(conn.private.plugoid_opts)["end_session_endpoint"] do
      <<_::binary>> = end_session_endpoint ->
        end_session_endpoint_uri = URI.parse(end_session_endpoint)

        query_params = Map.merge(
          URI.decode_query(end_session_endpoint_uri.query || ""),
          logout_params(conn, logout_opts)
        )

        end_session_endpoint =
          end_session_endpoint_uri
          |> Map.put(:query, URI.encode_query(query_params))
          |> URI.to_string()

        conn =
          conn
          |> local_logout()
          |> Phoenix.Controller.redirect(external: end_session_endpoint)
          |> Plug.Conn.halt()

        Logger.info(%{
          what: :plugoid_user_logout,
          result: :ok,
          details: %{
            logout_type: :rp_initiated,
            iss: conn.private.plugoid_opts[:issuer],
            sub: conn.private.plugoid_auth_sub
          }
        })

        conn

      nil ->
        raise UnsupportedError
    end
  end

  def rp_initiated_logout(%Plug.Conn{}, _) do
    raise UnauthenticatedConnectionError
  end

  defp logout_params(conn, logout_opts) do
    maybe_post_logout_redirect_uri = post_logout_redirect_uri(conn, logout_opts)
    maybe_id_token_hint = logout_opts[:id_token_callback].(
      conn.private.plugoid_opts[:issuer],
      conn.private.plugoid_auth_sub
    )

    logout_params =
      %{}
      |> Map.put("id_token_hint", maybe_id_token_hint)
      |> Map.put("post_logout_redirect_uri", maybe_post_logout_redirect_uri)
      |> Map.put("state", logout_opts[:state])
      |> Map.put("ui_locales", Enum.join(conn.private.plugoid_opts[:ui_locales] || [], " "))
      |> Enum.reject(fn {_k, v} -> v == nil or v == "" end)
      |> Enum.into(%{})

    if logout_params["post_logout_redirect_uri"] and not logout_params["id_token_hint"] do
      Map.delete(logout_params, "post_logout_redirect_uri")
    else
      logout_params
    end
  end

  defp post_logout_redirect_uri(conn, logout_opts) do
    redir_uri = logout_opts[:post_logout_redirect_uri]

    case conn.private.plugoid_opts[:client_config].get(conn.private.plugoid_opts[:client_id]) do
      %{"post_logout_redirect_uris" => [_ | _] = post_logout_redirect_uris} ->
        cond do
          redir_uri != nil and redir_uri in post_logout_redirect_uris ->
            redir_uri

          redir_uri != nil and redir_uri not in post_logout_redirect_uris ->
            raise "custom post logout redirect URI is not registered in client metadata"

          true ->
            hd(post_logout_redirect_uris)
        end

      _ ->
        redir_uri
    end
  end

  @doc false
  def id_token_callback(issuer, subject) do
    if Kernel.function_exported?(OAuth2TokenManager.Claims, :get_id_token, 2) do
      case OAuth2TokenManager.Claims.get_id_token(issuer, subject) do
        {:ok, <<_::binary>> = id_token} ->
          id_token

        {:ok, nil} ->
          nil

        {:error, e} ->
          raise e
      end
    end
  end
end
