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

  ## Logout functions

  The logout functions must be called from a page where the user is already authenticated. To
  check if a user is authenticated, the `Plugoid.authenticated?/1` function can be used.

  In doubt, use the `logout/1` function which manages logout depending on the OP's support.

  ### Options
  - `:id_token_callback`: a function that retrieves an ID token, possibly expired, for a given
  user. When not set, `Plugoid` tries to use the `OAuth2TokenManager` library if installed.
  - `:post_logout_redirect_uri`: the URI to redirect to after logout. Note that it can be
  configured at the client level (using the `"post_logout_redirect_uris"` metadata field).
  - `:state`: a string that will be passed back to the post logout URI when RP-initiated logout
  is used
  """

  alias Plugoid.{Session.AuthSession, Utils}

  @type logout_opts :: [logout_opt()]
  @type logout_opt ::
  #FIXME: subject not in OIDC
  {:id_token_callback, (OIDC.issuer(), OIDC.subject() -> OIDC.IDToken.serialized() | nil)}
  | {:post_logout_redirect_uri, String.t()}
  | {:state, String.t()}

  defmodule UnsupportedError do
    @moduledoc """
    RP-initiated logout is not supported by the OP
    """

    defexception message: "RP-initiated logout is not supported by the OP"
  end

  defmacro __using__(opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:path, "/openid_connect_logout")
      |> Keyword.put_new(:frontchannel_logout_session_required, true)
      |> IO.inspect()

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
  """
  @spec logout(Plug.Conn.t(), logout_opts) :: Plug.Conn.t()
  def logout(conn, logout_opts \\ []) do
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
  Locally destroys the current authentication session

  The user is not logged out from the OP or redirected to it. As a consequence, any further
  access to a protected page may silently re-authenticate the user, if the authentication
  user session is still active at the OP.

  It is recommended to redirect to a non-protected page after using this function. Otherwise,
  the user will be redirected for authentication to the OP.

  The session is destroyed for the current OP. To destroy all session of all OPs, use
  `local_logout_all/1` instead.
  """
  @spec local_logout(Plug.Conn.t()) :: Plug.Conn.t()
  def local_logout(%Plug.Conn{private: %{plugoid_authenticated: true}} = conn) do
    AuthSession.set_unauthenticated(conn, conn.private.plugoid_opts.issuer)
  end

  def local_logout(%Plug.Conn{} = conn) do
    conn
  end

  @doc """
  Logs out a user from all OPs

  The Plugoid authentication cookie is unset.
  """
  @spec local_logout_all(Plug.Conn.t()) :: Plug.Conn.t()
  def local_logout_all(%Plug.Conn{} = conn), do: AuthSession.destroy(conn)

  @doc """
  Performs an RP-initiated logout at the OP

  If the OP does not support logout, an `Plugoid.Logout.UnsupportedError` exception is raised.

  The session is not deleted locally; instead, the OP is in charge of killing the local
  session using front-channel logout, back-channel logout or session management.
  """
  @spec rp_initiated_logout(Plug.Conn.t(), logout_opts()) :: Plug.Conn.t()
  def rp_initiated_logout(
    %Plug.Conn{private: %{plugoid_authenticated: true}} = conn,
    logout_opts \\ []
  ) do
    case Utils.server_metadata(conn.private.plugoid_opts.issuer)["end_session_endpoint"] do
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

        conn
        |> local_logout()
        |> Phoenix.Controller.redirect(external: end_session_endpoint)
        |> Plug.Conn.halt()

      nil ->
        raise UnsupportedError
    end
  end

  defp logout_params(conn, logout_opts) do
    maybe_post_logout_redirect_uri = post_logout_redirect_uri(conn, logout_opts)
    maybe_id_token_hint = id_token(conn, logout_opts)

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

    case logout_opts[:client_config_module].(conn.private.plugoid_opts.client_id) do
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

  defp id_token(conn, logout_opts) do
    issuer = conn.private.plugoid_opts.issuer
    subject = conn.private.plugoid_auth_sub

    case logout_opts[:id_token_callback] do
      callback when is_function(callback, 2) ->
        callback.(issuer, subject)

      nil ->
        if Kernel.function_exported?(OAuth2TokenManager.Claims, :get_id_token, 2) do
          case OAuth2TokenManager.Claims.get_id_token(issuer, subject) do
            {:ok, <<_::binary>> = id_token} ->
              id_token

            _ ->
              nil
          end
        end
    end
  end
end
