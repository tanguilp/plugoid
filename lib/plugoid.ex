defmodule Plugoid do
  @moduledoc """
  ## Basic use

      defmodule MyAppWeb.Router do
        use MyAppWeb, :router
        use Plugoid.RedirectURI

        pipeline :oidc_auth do
          plug Plugoid,
            issuer: "https://repentant-brief-fishingcat.gigalixirapp.com",
            client_id: "client1",
            client_config: PlugoidDemo.OpenIDConnect.Client
        end

        scope "/private", MyAppWeb do
          pipe_through :browser
          pipe_through :oidc_auth

          get "/", PageController, :index
          post "/", PageController, :index
        end
      end

  ## Plug options

  ### Mandatory plug options

  - `:client_id` **[Mandatory]**: the client id to be used for interaction with the OpenID
  Provider (OP)
  - `:client_config` **[Mandatory]**: a module that implements the
  [`OIDC.ClientConfig`](https://hexdocs.pm/oidc/OIDC.ClientConfig.html) behaviour and returns
  the client configuration
  - `:issuer` **[Mandatory]**: the OpenID Provider (OP) issuer. Server metadata and keys are
  automatically retrieved from it if the OP supports it

  ### Additional plug options

  - `:acr_values`: one of:
    - `nil` [*Default*]: no acr values requested
    - `[String.t()]`: a list of acr values
  - `:acr_values_callback`: a `t:opt_callback/0` that dynamically returns a list of ACRs. Called
  only if `:acr_values` is not set
  - `:claims`: the `"claims"` parameter
  - `:claims_callback`: a `t:opt_callback/0` that dynamically returns the claim parameter. Called
  only if `:claims` is not set
  - `:display`: display parameter. Mostly unused. Defaults to `nil`
  - `:error_view`: the error view to be called in case of error. See the
  [Error handling](#module-error-handling) section bellow. If not set, it will be automatically
  set to `MyApp.ErrorView` where `MyApp` is the base module name of the application
  - `:id_token_iat_max_time_gap`: max time gap to accept an ID token, in seconds.
  Defaults to `30`
  - `:login_hint_callback`: a `t:opt_callback/0` that dynamically returns the login hint
  parameter
  - `:max_age`: the OIDC max age (`non_neg_integer()`) parameter
  - `:max_concurrent_state_session`: maximum of state sessions stored concurrently. Defaults to
  `4`, set to `nil` for no limits. See [On state cookies](#module-on-state-cookies)
  - `:oauth2_metadata_updater_opts`: options that will be passed to `Oauth2MetadataUpdater`.
  Some authorization server do not follow standards when forming the metadata's URI. In such a
  case, you might need to use the `:url_construction` option of `Oauth2MetadataUpdater`
  - `:on_unauthenticated`: action to be taken when the request is not authenticated. One
  of:
    - `:auth` **[Default]**: redirects to the authorization endpoint of the OP
    - `:fail`: returns an HTTP 401 error
    - `:pass`: hands over the request to the next plug. The request is unauthenticated
    (this can be checked using the `authenticated?/1` function)
  - `:on_unauthorized`: action to be taken when the user is not authorized, because of invalid
  ACR. One of:
    - `:auth` **[Default]**: redirects to the authorization endpoint of the OP
    - `:fail`: returns an HTTP 403 error
  - `:preserve_initial_request`: a boolean. Defaults to `false`. See further
  [Preserving request parameters](#module-preserving-request-parameters)
  - `:prompt`: one of the standard values (`"none"`, `"login"`, `"consent"`, or
  `"select_account"`)
  - `:prompt_callback`: a `t:opt_callback/0` that dynamically returns the prompt parameter.
  Called only if `:prompt` is not set
  - `:redirect_uri`: the redirect URI the OP has to use for redirect. If not set,
  defaults to
  `Myapp.Router.Helpers.openid_connect_redirect_uri(Myapp.Endpoint, :call)?iss=<ISS>`
  where `<ISS>` is replaced by the URL-encoded issuer. This scheme is used to prevent
  mix-up attacks (see the [Security considerations](#module-security-considerations)).
  It asumes that such a route was installed. See also `Plugoid.RedirectURI` for automatic
  installation of this route and the available
  [helpers](Plugoid.RedirectURI.html#module-determining-the-redirect-uri).
  - `:response_mode`: one of:
    - `"query"`
    - `"fragment"`
    - `"form_post"`
  - `:response_mode_callback`: a `t:opt_callback/0` that dynamically returns the response mode
  for the request. Called only if `:response_mode` is not set
  - `:response_type`: one of:
    - `"code"` (code flow)
    - `"id_token"` (implicit flow)
    - `"id_token token"` (implicit flow)
    - `"code token"` (hybrid flow)
    - `"code id_token"` (hybrid flow)
    - `"code id_token token"` (hybrid flow)
  - `:response_type_callback`: a `t:opt_callback/0` that dynamically returns the response type
  for the request. Called only if `:response_type` is not set
  - `:session_lifetime`: the local session duration in seconds. After this time interval, the
  user is considered unauthenticated and is redirected again to the OP. Defaults to `3600`
  - `:scope`: a list of scopes (`[String.t()]`) to be requested. The `"openid"` scope
  is automatically requested. The `"offline_access"` scope is to be added here if one
  wants OAuth2 tokens to remain active after the user's logout from the OP
  - `:server_metadata`: a `t:OIDC.server_metadata/0` of server metadata that will take precedence
  over those of the issuer (published on the `"https://issuer/.well-known/openid-configuration"` URI).
  Useful to override one or more server metadata fields
  - `ui_locales`: a list of UI locales
  - `:use_nonce`: one of:
    - `:when_mandatory` [*Default*]: a nonce is included when using the implicit and
    hybrid flows
    - `:always`: always include a nonce (i.e. also in the code flow in which it is
    optional)

  ## Cookie configuration

  Plugoid uses 2 cookies, different from the Phoenix session cookie (which allows more control
  over the security properties of these cookies):
  - authentication cookie: stores the information about authenticated session, after being
  successfully redirected from the OP
  - state session: store the information about the in-flight requests to the OP. It is set
  before redirecting to the OP, and then used and deleted when coming back from it

  It uses the standard `Plug.Session.Store` behaviour: any existing plug session stores can
  work with Plugoid.

  Plugoid cookies use the following application environment options that can be configured
  under the `:plugoid` key:
  - authentication cookie:
    - `:auth_cookie_name`: the name of the authentication cookie. Defaults to
    `"plugoid_auth"`
    - `:auth_cookie_opts`: `opts` arg of `Plug.Conn.put_resp_cookie/4`. Defaults to
    `[extra: "SameSite=Lax"]`
    - `:auth_cookie_store`: a module implementing the `Plug.Session.Store` behaviour.
    Defaults to `:ets` (which is `Plug.Session.ETS`)
    - `:auth_cookie_store_opts`: options for the `:auth_cookie_store`. Defaults to
    `[table: :plugoid_auth_cookie]`. Note that the `:plugoid_auth_cookie_store`
    ETS table is expected to exist, i.e. to be created beforehand. It is also not suitable for
    production, as cookies are never deleted
  - state cookie:
    - `:state_cookie_name`: the base name of the state cookie. Defaults to
    `"plugoid_state"`
    - `:state_cookie_opts`: `opts` arg of `Plug.Conn.put_resp_cookie/4`. Defaults to
    `[extra: "SameSite=None"]`. `SameSite` is set to `None` because OpenID Connect can redirect
    with a HTTP post request (`"form_post"` response mode) and cross-domain cookies are not
    sent except with this setting
    - `:state_cookie_store`: a module implementing the `Plug.Session.Store` behaviour.
    Defaults to `:cookie` (which is `Plug.Session.COOKIE`)
    - `:state_cookie_store_opts`: options for the `:state_cookie_store`. Defaults to `[]`

  Note that by default, `:http_only` is set to `true` as well as the `:secure` cookie flag if
  the connection is using https.

  ### On state cookies
  Plugoid allows having several in-flight requests to one or more OPs, because a user could
  inadvertently open 2 pages for authentication, or authenticate in parallel to several OPs
  (social network OIDC providers, for instance).

  Also, as state cookies are by definition created by unauthenticated users, it is easy for
  an attacker to generate a lot of state sessions and overwhelm a relying party (the site using
  Plugoid), especially if the sessions are stored in the backend.

  This is why it is safer to store state session on the client side. By default, Plugoid uses
  the `:cookie` session store for state sessions: in-flight OIDC requests are stored in the
  browser's cookies. Note that the secret key base **must** be set in the connection.

  This, however, has the some limitations:
  - cookies are limited to 4kb of data
  - header size is also limited by web servers. Cowboy (Phoenix's web server) limits headers
  to 4kb as well

  To deal with the first problem, Plugoid:
  - limits the amount of information stored in the state session to the minimum
  - uses different cookies for different OIDC requests (`"plugoid_state_1"`,
  `"plugoid_state_2"`, `"plugoid_state_3"`, `"plugoid_state_4"` and so on)
  - limits the number of concurrent requests and deletes the older ones when needed, with the
  `:max_concurrent_state_session` option

  However, the 4kb limit is still low and only a few state cookies can be stored concurrently.
  It is recommended to test it in your application before releasing it in production to find
  the right `:max_concurrent_state_session`. Also note that it is possible to raise this limit
  in Cowboy (see [Configure max http header size in Elixir Phoenix](https://til.hashrocket.com/posts/cvkpwqampv-configure-max-http-header-size-in-elixir-phoenix)).

  ## Preserving request parameters

  When set to `true` through the `:preserve_initial_request` option, query and body parameters
  are replayed when redirected back from the OP.

  Like for state session, it cannot be stored on server side because it would expose the server
  to DOS attacks (even more, as query and body parameters can be way larger). Therefore,
  these parameters are stored in the browser's session storage. The flow is as follows:
  - the user is not authenticated and hits a Plugoid-protected page
  - Plugoid displays a special blank page with javascript code. The javascript code stores
  the parameters in the session storage
  - the user is redirected to the OP (via javascript), authenticates, and is redirected to
  Plugoid's redirect URI
  - OIDC response is checked and, if valid, Plugoid's redirect URI plug redirects the user to
  the initial page
  - Plugoid displays a blank page containing javascript code, which:
    - redirects to the initial page with query parameters if the initial request was a `GET`
    request
    - builds an HTML form with initial body parameters and post it to the initial page (with
    query parameters as well) if the initial request was a `POST` request

  Note that request data is stored **unencrypted** in the browser. If your forms may contain
  sensitive data, consider not using this feature. This is why this option is set to `false`
  by default.

  Limitations:
  - The body must be parsed (`Plug.Parsers`) before reaching the Plugoid plug
  - The body's encoding must be `application/x-www-form-urlencoded`. File upload using the
  `multipart/form-data` as the encoding is not supported, and cannot be replayed
  - Only `GET` and `POST` request are supported ; in other cases Plugoid will fail restoring
  state silently

  ## Client authentication

  Upon registration, a client registers a unique authentication scheme to be used by
  itself to authenticate to the OP. In other words, a client cannot use different
  authentication schemes on different endpoints.

  OAuth2 REST endpoints usually demand client authentication. Client authentication is handled
  by the `TeslaOAuth2ClientAuth` library. The authentication middleware to be used is
  determined based on the client configuration. For instance, to authenticate to the
  token endpoint, the `"token_endpoint_auth_method"` is used to determine which authentication
  middleware to use.

  Thus, to configure a client for Basic authentication, the client configuration callback must
  return a configuration like:

      %{
        "client_id" => "some_client_id_provided_by_the_OP",
        "token_endpoint_auth_method" => "client_secret_basic",
        "client_secret" => "<the client secret>",
        ...
      }

  However, the default value for the token endpoint auth method is `"client_secret_basic"`, thus
  the following is enough:

      %{
        "client_id" => "some_client_id_provided_by_the_OP",
        "client_secret" => "<the client secret>",
        ...
      }

  Also note that the implicit flow does not require client authentication.

  ## Default responses type and mode

  By default and if supported by the OP, these values are set to:
  - response mode: `"form_post"`
  - response type: `"id_token"`

  These values allows direct authentication without additional roundtrip to the server, at the
  expense of:
  - not receiving access tokens, which is fine if only authentication is needed
  - slightly lesser security: the ID token can be replayed, while an authorization code cannot.
  This can be mitigated using a JTI register (see the
  [Security considerations](#module-security-considerations)) section.

  Otherwise it falls back to the `"code"` response type.

  ## Session

  When using OpenID Connect, the OP is authoritative to determine whether the user is
  authenticated or not. There are 2 ways for or Relying Party (the site using a library like
  Plugoid) to determine it:
  - using [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0.html),
  which is unsupported by Plugoid
  - periodically redirecting to the OP to check for authentication. If the user is authenticated
  on the OP, he's not asked to reauthenticate (in the browser it materializes by being swiftly
  redirected to the OP and back to the relying party (the site using `Plugoid`)).

  By default, Plugoid cookies have no timeout, and are therefore session cookies. When the user
  closes his browser, there are destroyed.

  However, another parameter is taken into account: the `:session_lifetime` parameter, which
  defaults to 1 hour. This ensures that a user can not remain indefinitely authenticated, and
  prevents an attacker from using a stolen cookie for too long.

  That is, authenticated session cookie's lifetime is not correlated from the `:session_lifetime`
  and keeping this cookie as a session cookie is fine - it's the OP's work to handle long-lived
  authenticated sessions.

  ## Logout

  Plugoid does not support OpenID Connect logout. However, the functions:
  - `Plugoid.logout/1`
  - `Plugoid.logout/2`

  allow loging out a user **locally** by removing authenticated session data or the whole
  authentication cookie and session.

  Note that, however, the user will be redirected again to the OP (and might be seamlessly
  authenticated, if his session is active on the OP) when reaching a path protected by Plugoid.

  ## Error handling

  Errors can occur:
  - when redirected back from the OP. This is an OP error (for instance the user denied the
  authorization to share his personal information)
  - when analyzing the request back from the OP, if an error occurs (for instance, the ID token
  was expired)
  - ACR is no sufficient (user is authenticated, but not authorized)
  - when `:on_unauthenticated` or `:on_unauthorized` are set to `:fail`

  Depending on the case, Plugoid renders one of the following templates:
  - `:"401"`
  - `:"403"`
  - `:"500"`

  It also sets the `@error` assign in them to an **exception**, one of Plugoid or one of the
  `OIDC` library.

  When the error occured on the OP, the `:401` error template is called with an
  `OIDC.Auth.OPResponseError` exception.

  ## Security considerations

  - Consider renaming the cookies to make it harder to detect which library is used
  - Consider setting the `:domain` and `:path` settings of the cookies
  - When using the implicit or hybrid flow, consider setting a JTI register to prevent replay
  attacks of ID tokens. This is configured in the `Plugoid.RedirectURI` plug
  - Consider filtering Phoenix's parameters in the logs. To do so, add in the configuration
  file `config/config.exs` the following line:

  ```elixir
  config :phoenix, :filter_parameters, ["id_token", "code", "token"]
  ```

  ### Preventing mix-up attacks

  Mix-up attacks consists in using the fact that OpenID Connect responses on the
  redirect URI are not authenticated, and can therefore originate from anyone. An
  malicious OP can trick an OpenID Connect RP by convincing it to send him tokens
  received from another OP. This can happen only when more than one OP is used.

  For further discussion, see
  [Mix-Up, Revisited](https://danielfett.de/2020/05/04/mix-up-revisited/).

  `Plugoid` is immune to such an attack because it adds the issuer to the redirect URI
  as a query parameter and verifies that all request query parameters exist in
  the response from the OP.

  Beware, however, if you manually change the redirect URI using the
  `:redirect_uri_callback` option.

  """

  defmodule AuthenticationRequiredError do
    defexception message: "authentication is required to access this page"
  end

  defmodule UnauthorizedError do
    defexception message: "access to this page is denied"
  end

  alias OIDC.Auth.OPResponseError
  alias Plugoid.{
    OIDCRequest,
    Session.AuthSession,
    Session.StateSession,
    Utils
  }

  @behaviour Plug

  @type opts :: [opt | OIDC.Auth.challenge_opt()]

  @type opt ::
  {:acr_values_callback, opt_callback()}
  | {:claims_callback, opt_callback()}
  | {:error_view, module()}
  | {:id_token_hint_callback, opt_callback()}
  | {:login_hint_callback, opt_callback()}
  | {:max_concurrent_state_session, non_neg_integer() | nil}
  | {:on_unauthenticated, :auth | :fail | :pass}
  | {:on_unauthorized, :auth | :fail}
  | {:prompt_callback, opt_callback()}
  | {:redirect_uri, String.t()}
  | {:redirect_uri_callback, opt_callback()}
  | {:response_mode_callback, opt_callback()}
  | {:response_type_callback, opt_callback()}
  | {:server_metadata, OIDC.server_metadata()}
  | {:session_lifetime, non_neg_integer()}

  @type opt_callback :: (Plug.Conn.t(), opts() -> any())

  @implicit_response_types ["id_token", "id_token token"]
  @hybrid_response_types ["code id_token", "code token", "code id_token token"]

  @impl Plug
  def init(opts) do
    unless opts[:issuer], do: raise "Missing issuer"
    unless opts[:client_id], do: raise "Missing client_id"
    unless opts[:client_config], do: raise "Missing client configuration callback"

    opts
    |> Keyword.put_new(:id_token_iat_max_time_gap, 30)
    |> Keyword.put_new(:max_concurrent_state_session, 4)
    |> Keyword.put_new(:on_unauthenticated, :auth)
    |> Keyword.put_new(:on_unauthorized, :auth)
    |> Keyword.put_new(:preserve_initial_request, false)
    |> Keyword.put_new(:redirect_uri_callback, &__MODULE__.redirect_uri/2)
    |> Keyword.put_new(:response_mode_callback, &__MODULE__.response_mode/2)
    |> Keyword.put_new(:response_type_callback, &__MODULE__.response_type/2)
    |> Keyword.put_new(:session_lifetime, 3600)
  end

  @impl Plug
  def call(%Plug.Conn{private: %{plugoid_authenticated: true}} = conn, _opts) do
    conn
  end

  def call(conn, opts) do
    case Plug.Conn.fetch_query_params(conn) do
      %Plug.Conn{query_params: %{"redirected" => _}} = conn ->
        if opts[:preserve_initial_request] do
          conn
          |> Phoenix.Controller.put_view(PlugoidWeb.PreserveRequestParamsView)
          |> Phoenix.Controller.render("restore.html")
          |> Plug.Conn.halt()
        else
          conn
          |> maybe_set_authenticated(opts)
          |> do_call(opts)
        end

      %Plug.Conn{query_params: %{"oidc_error" => error_token}} ->
        {:ok, token_content} =
          Phoenix.Token.verify(conn, "plugoid error token", error_token, max_age: 60)

        error = :erlang.binary_to_term(token_content)

        respond_unauthorized(conn, error, opts)

      conn ->
        conn
        |> maybe_set_authenticated(opts)
        |> do_call(opts)
    end
  end

  @spec do_call(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()
  defp do_call(conn, opts) do
    authenticated = authenticated?(conn)
    authorized = authorized?(conn, opts)
    on_unauthenticated = opts[:on_unauthenticated]
    on_unauthorized = opts[:on_unauthorized]
    redirected = conn.query_params["redirected"] != nil

    cond do
      authenticated and authorized ->
        conn

      not authenticated and not redirected and on_unauthenticated == :auth ->
        authenticate(conn, opts)

      not authenticated and not redirected and on_unauthenticated == :pass ->
        conn

      not authenticated and not redirected and on_unauthenticated == :fail ->
        respond_unauthorized(conn, %AuthenticationRequiredError{}, opts)

      not authenticated and redirected and on_unauthenticated in [:auth, :fail] ->
        respond_unauthorized(conn, %AuthenticationRequiredError{}, opts)

      not authenticated and redirected and on_unauthenticated in :pass ->
        conn

      authenticated and not authorized and not redirected and on_unauthorized == :auth ->
        authenticate(conn, opts)

      authenticated and not authorized ->
        respond_forbidden(conn, opts)
    end
  end

  @spec maybe_set_authenticated(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()
  defp maybe_set_authenticated(conn, opts) do
    case AuthSession.info(conn, opts[:issuer]) do
      %AuthSession.Info{} = auth_session_info ->
        now_monotonic = System.monotonic_time(:second)

        if now_monotonic < auth_session_info.auth_time_monotonic + opts[:session_lifetime] do
          conn
          |> Plug.Conn.put_private(:plugoid_authenticated, true)
          |> Plug.Conn.put_private(:plugoid_auth_iss, opts[:issuer])
          |> Plug.Conn.put_private(:plugoid_auth_sub, auth_session_info.sub)
        else
          Plug.Conn.put_private(conn, :plugoid_authenticated, false)
        end

      nil ->
        Plug.Conn.put_private(conn, :plugoid_authenticated, false)
    end
  end

  @spec authorized?(Plug.Conn.t(), opts()) :: boolean()
  defp authorized?(%Plug.Conn{private: %{plugoid_authenticated: true}} = conn, opts) do
    %AuthSession.Info{acr: current_acr} = AuthSession.info(conn, opts[:issuer])

    case opts[:claims] do
      %{
        "id_token" => %{
          "acr" => %{
            "essential" => true,
            "value" => required_acr
          }
        }
      } ->
        current_acr == required_acr

      %{
        "id_token" => %{
          "acr" => %{
            "essential" => true,
            "values" => acceptable_acrs
          }
        }
      } ->
        current_acr in acceptable_acrs

      _ ->
        true
    end
  end

  defp authorized?(_conn, _opts) do
    false
  end

  @spec respond_unauthorized(
    Plug.Conn.t(),
    OPResponseError.t() | Exception.t(),
    opts()
  ) :: Plug.Conn.t()
  defp respond_unauthorized(conn, error, opts) do
    conn
    |> Plug.Conn.put_status(:unauthorized)
    |> Phoenix.Controller.put_view(error_view(conn, opts))
    |> Phoenix.Controller.render(:"401", error: error)
    |> Plug.Conn.halt()
  end

  @spec respond_forbidden(Plug.Conn.t(), opts()) :: Plug.Conn.t()
  defp respond_forbidden(conn, opts) do
    conn
    |> Plug.Conn.put_status(:forbidden)
    |> Phoenix.Controller.put_view(error_view(conn, opts))
    |> Phoenix.Controller.render(:"403", error: %UnauthorizedError{})
    |> Plug.Conn.halt()
  end

  @spec authenticate(
    Plug.Conn.t(),
    opts()
  ) :: Plug.Conn.t()
  defp authenticate(conn, opts) do
    opts =
      Enum.reduce(
        [:acr_values, :claims, :id_token_hint, :login_hint, :prompt, :redirect_uri,
         :response_mode, :response_type],
        opts,
        &apply_opt_callback(&2, &1, conn)
      )

    challenge = OIDC.Auth.gen_challenge(opts)

    op_request_uri = OIDC.Auth.request_uri(challenge, opts) |> URI.to_string()

    conn =
      StateSession.store_oidc_request(
        conn,
        %OIDCRequest{challenge: challenge, initial_request_path: conn.request_path},
        opts[:max_concurrent_state_session]
        )

    if opts[:preserve_initial_request] do
      conn
      |> Phoenix.Controller.put_view(PlugoidWeb.PreserveRequestParamsView)
      |> Phoenix.Controller.render("save.html", conn: conn, op_request_uri: op_request_uri)
      |> Plug.Conn.halt()
    else
      conn
      |> Phoenix.Controller.redirect(external: op_request_uri)
      |> Plug.Conn.halt()
    end
  end

  @spec apply_opt_callback(opts(), atom(), Plug.Conn.t()) :: opts()
  defp apply_opt_callback(opts, opt_name, conn) do
    if opts[opt_name] do
      opts
    else
      opt_callback_name = String.to_atom(Atom.to_string(opt_name) <> "_callback")

      case opts[opt_callback_name] do
        callback when is_function(callback, 2) ->
          Keyword.put(opts, opt_name, callback.(conn, opts))

        _ ->
          opts
      end
    end
  end

  #Returns a response type supported by the OP
  #In order of preference:
  #- `"id_token"`: allows authentication in one unique round-trip
  #- `"code"`: forces client authentication that can be considered an additional
  #layer of security (when simply redirecting to an URI is not trusted)
  #- or the first supported response type set in the OP metadata
  @doc false
  @spec response_type(Plug.Conn.t(), opts()) :: String.t()
  def response_type(_conn, opts) do
    response_types_supported = Utils.server_metadata(opts)["response_types_supported"] ||
      raise "Unable to retrieve `response_types_supported` from server metadata or configuration"
    response_modes_supported = Utils.server_metadata(opts)["response_modes_supported"] || []

    cond do
    "id_token" in response_types_supported and "form_post" in response_modes_supported ->
      "id_token"

    "code" in response_types_supported ->
      "code"

    true ->
      List.first(response_types_supported)
    end
  end

  #Returns the response mode from the options
  #In the implicit and hybrid flows, returns `"form_post"` if supported by the server, `"query"`
  #otherwise. In the code flow, returns `nil` (the default used by the server is `"query"`).
  @doc false
  @spec response_mode(Plug.Conn.t(), opts()) :: String.t() | nil
  def response_mode(conn, opts) do
    response_type = opts[:response_type] || response_type(conn, opts)
    response_modes_supported = Utils.server_metadata(opts)["response_modes_supported"] || []

    if response_type in @implicit_response_types or response_type in @hybrid_response_types do
      if "form_post" in response_modes_supported do
        "form_post"
      else
        "query"
      end
    end
  end

  @doc false
  @spec redirect_uri(Plug.Conn.t() | module(), opts()) :: String.t()
  def redirect_uri(%Plug.Conn{} = conn, opts) do
    router = Phoenix.Controller.router_module(conn)

    base_redirect_uri =
      apply(
        Module.concat(router, Helpers),
        :openid_connect_redirect_uri_url,
        [Phoenix.Controller.endpoint_module(conn), :call]
      )

    base_redirect_uri <> "?iss=" <> URI.encode(opts[:issuer])
  end

  @doc """
  Returns `true` if the connection is authenticated with `Plugoid`, `false` otherwise
  """
  @spec authenticated?(Plug.Conn.t()) :: boolean()
  def authenticated?(conn), do: conn.private[:plugoid_authenticated] == true

  @doc """
  Returns the issuer which has authenticated the current authenticated user, or `nil` if
  the user is unauthenticated
  """
  @spec issuer(Plug.Conn.t()) :: String.t() | nil
  def issuer(conn), do: conn.private[:plugoid_auth_iss]

  @doc """
  Returns the subject (OP's "user id") of current authenticated user, or `nil` if
  the user is unauthenticated
  """
  @spec subject(Plug.Conn.t()) :: String.t() | nil
  def subject(conn), do: conn.private[:plugoid_auth_sub]

  @doc """
  Returns `true` if the current request happens after a redirection from the OP, `false`
  otherwise
  """
  @spec redirected_from_OP?(Plug.Conn.t()) :: boolean()
  def redirected_from_OP?(conn) do
    case conn.params do
      %{"redirected" => _} ->
        true

      %{"oidc_error" => _} ->
        true

      %{"restored" => _} ->
        true

      _ ->
        false
    end
  end

  @doc """
  Logs out a user from an issuer

  The connection should be eventually sent to have the cookie updated
  """
  @spec logout(Plug.Conn.t(), OIDC.issuer()) :: Plug.Conn.t()
  def logout(conn, issuer), do: AuthSession.set_unauthenticated(conn, issuer)

  @doc """
  Logs out a user from all issuers

  The connection should be eventually sent to have the cookie unset
  """
  @spec logout(Plug.Conn.t()) :: Plug.Conn.t()
  def logout(conn), do: AuthSession.destroy(conn)

  @spec error_view(Plug.Conn.t(), opts()) :: module()
  defp error_view(conn, opts) do
    case opts[:error_view] do
      nil ->
        Utils.error_view_from_conn(conn)

      view when is_atom(view) ->
        view
    end
  end
end
