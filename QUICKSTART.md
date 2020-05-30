# Quick start

## Step 1: install the redirect URI plug

In your `router.ex` file, add at the beginning:

```elixir
  use Plugoid.RedirectURI
```

## Step 2: create an OpenID Connect pipeline

Still in `router.ex`, add a Plugoid pipeline:

```elixir
  pipeline :oidc_auth do
    plug Plugoid,
      issuer: "<issuer>",
      client_id: "<client_id>",
      client_config: MyApp.ClientCallback
  end
```

where `<issuer>` is the OpenID Provider's (OP) issuer URL and `<client_id>` is the client
identifier provided upon application registration at the OP.

## Step 3: protect some routes with the pipeline

Again in `router.ex`, add the pipeline to some routes:

```elixir
  scope "/private", MyAppWeb do
    pipe_through :browser
    pipe_through :oidc_auth

    get "/", PageController, :index
  end
```

## Step 4: create a client callback

Create the `myapp/lib/myapp/client_callback.ex` file (where `myapp` is replaced by the name
of your application) and add the following code:

```elixir
defmodule MyApp.ClientCallback do
  @behaviour OIDC.Auth.ClientConfig

  @impl true
  def get("<client_id>") do
    %{
      "client_id" => "<client_id>",
      "client_secret" => "<client_secret>"
    }
  end
end
```

where `<client_id>` is the same client identifier as before, and `<client_secret>` is the
application password provided by the OP upon registration of the application.

If another type of credential was provided, refer to `TeslaOAuth2ClientAuth` documentation.

In production environment, it is unsafe to hardcode application password in an Elixir module.
Use `Application.fetch_env!/2` or another secure mean instead.
