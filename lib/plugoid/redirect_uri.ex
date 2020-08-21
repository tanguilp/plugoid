defmodule Plugoid.RedirectURI do
  @moduledoc """
  Plug to configure the application redirect URI

  An OAuth2 / OpenID Connect redirect URI is a vanity, non-dynamic URI. The authorization
  server redirects to this URI after authentication and authorization success or failure.

  ## Automatic configuration in a router

      defmodule Myapp.Router do
        use Plugoid.RedirectURI
      end

  installs a route to `/openid_connect_redirect_uri` in a Phoenix router.

  ## Determining the redirect URI

  When using `Plugoid.RedirectURI`, an `plugoid_redirect_uri/2` function is automatically
  installed in the router. It takes the endpoint as the first parameter and the issuer
  as the second:

      iex> PlugoidDemoWeb.Router.plugoid_redirect_uri(PlugoidDemoWeb.Endpoint, "https://issuer.example.com/auth")
      "http://localhost:4000/openid_connect_redirect_uri?iss=https://issuer.example.com/auth"

  It can be called without the endpoint, in which case it is inferred from the router's
  module name:

      iex> PlugoidDemoWeb.Router.plugoid_redirect_uri("https://issuer.example.com/auth")
      "http://localhost:4000/openid_connect_redirect_uri?iss=https://issuer.example.com/auth"

  ## Options

  - `:error_view`: the error view to be called in case of error. The `:"500"` template is
  rendered in case of error (bascially, when the `state` parameter is missing from the response).
  If not set, it will be automatically set to `MyApp.ErrorView` where `MyApp` is the
  base module name of the application
  - `:jti_register`: a module implementing the `JTIRegister` behaviour, to check the ID
  Token against replay attack when a nonce is used (in the implicit and hybrid flows).
  See also [`JTIRegister`](https://github.com/tanguilp/jti_register)
  - `:path`: the path of the redirect URI. Defaults to `"openid_connect_redirect_uri"`
  - `:token_callback`: a `t:token_callback/0` function to which are passed the received
  tokens, for further use (for example, to store a refresh token)

  Options of `t:OIDC.Auth.verify_opts/0` which will be passed to `OIDC.Auth.verify_response/3`.
  """

  @behaviour Plug

  alias OIDC.Auth.{
    Challenge,
    OPResponseSuccess
  }
  alias Plugoid.{
    Session.AuthSession,
    Session.StateSession,
    Utils
  }

  @type opts :: [opt() | OIDC.Auth.verify_opt()]
  @type opt ::
  {:error_view, module()}
  | {:jti_register, module()}
  | {:path, String.t()}
  | {:token_callback, token_callback()}

  @type token_callback :: (
    OPResponseSuccess.t(),
    issuer :: String.t(),
    client_id :: String.t(),
    opts()
    -> any())

  defmodule MissingStateParamaterError do
    defexception message: "state parameter is missing from OP's response"
  end

  defmacro __using__(opts) do
    quote do
      def plugoid_redirect_uri(endpoint \\ nil, issuer) do
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

        base_redirect_uri =
          apply(
            Module.concat(__MODULE__, Helpers),
            :openid_connect_redirect_uri_url,
            [endpoint, :call]
          )

        base_redirect_uri <> "?iss=" <> URI.encode(issuer)
      end

      pipeline :oidc_redirect_pipeline do
        plug :accepts, ["html"]
        plug :fetch_query_params
        plug Plug.Parsers, parsers: [:urlencoded], pass: ["*/*"]
      end

      scope unquote(opts[:path]) || "/openid_connect_redirect_uri", Plugoid do
        pipe_through :oidc_redirect_pipeline

        get "/", RedirectURI, :call,
          as: :openid_connect_redirect_uri,
          private: %{plugoid: unquote(opts)}
        post "/", RedirectURI, :call,
          as: :openid_connect_redirect_uri,
          private: %{plugoid: unquote(opts)}
      end
    end
  end

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    opts = conn.private[:plugoid]

    with {:ok, op_response} <- extract_params(conn),
         %{"state" => state} = op_response,
         {:ok, {conn, request}} <- StateSession.get_and_delete_oidc_request(conn, state)
    do
      case OIDC.Auth.verify_response(op_response, request.challenge, opts) do
        {:ok, %OPResponseSuccess{} = response} ->
          maybe_register_nonce(response.id_token_claims, opts)
          maybe_execute_token_callback(response, request.challenge, opts)

          conn
          |> AuthSession.set_authenticated(request.challenge.issuer, response)
          |> Phoenix.Controller.redirect(to: request.initial_request_path <> "?redirected")

        {:error, error} ->
          # we compress to the maximum to avoid browser URL length limitations
          error_token = Phoenix.Token.sign(
            conn,
            "plugoid error token",
            :erlang.term_to_binary(error, compressed: 9)
          )

          redirect_to = request.initial_request_path <> "?oidc_error=" <> error_token

          Phoenix.Controller.redirect(conn, to: redirect_to)
      end
    else
      {:error, reason} ->
        conn
        |> Plug.Conn.put_status(:internal_server_error)
        |> Phoenix.Controller.put_view(error_view(conn))
        |> Phoenix.Controller.render(:"500", error: reason)
    end
  end

  @spec extract_params(Plug.Conn.t()) :: {:ok, map()} | {:error, atom()}
  defp extract_params(conn) do
    case conn.method do
      "GET" ->
        conn.query_params

      "POST" ->
        conn.body_params
    end
    |> case do
      %{"state" => _} = params ->
        {:ok, params}

      %{} ->
        {:error, %MissingStateParamaterError{}}
    end
  end

  @spec error_view(Plug.Conn.t()) :: module()
  defp error_view(conn),
    do: conn.private[:plugoid][:error_view] || Utils.error_view_from_conn(conn)

  @spec maybe_register_nonce(OIDC.id_token_claims(), Keyword.t()) :: any()
  defp maybe_register_nonce(%{"nonce" => nonce, "exp" => exp}, opts) do
    case opts[:jti_register] do
      impl when is_atom(impl) ->
        impl.register(nonce, exp)

      _ ->
        :ok
    end
  end

  defp maybe_register_nonce(_, _) do
    :ok
  end

  @spec maybe_execute_token_callback(
    OPResponseSuccess.t(),
    Challenge.t(),
    opts()
  ) :: any()
  defp maybe_execute_token_callback(response, challenge, opts) do
    if opts[:token_callback] do
      opts[:token_callback].(
        response,
        challenge.issuer,
        challenge.client_id,
        opts[:token_callback_opts] || []
      )
    end
  end
end
