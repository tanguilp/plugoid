# Plugoid

OpenID Connect Plug for Phoenix

Plugoid lets you protect some routes with OpenID Connect authentication, for instance:

```elixir
defmodule PlugoidDemoWeb.Router do
  use PlugoidDemoWeb, :router
  use Plugoid.RedirectURI

  pipeline :oidc_auth do
    plug Plugoid,
      issuer: "https://repentant-brief-fishingcat.gigalixirapp.com",
      client_id: "client1",
      client_config: PlugoidDemo.OpenIDConnect.Client
  end

  scope "/private", PlugoidDemoWeb do
    pipe_through :browser
    pipe_through :oidc_auth

    get "/", PageController, :index
    post "/", PageController, :index
  end
end
```

## Documentation

- Full documentation on [hex.pm](https://hexdocs.pm/plugoid/)
- [Quick start guide](https://hexdocs.pm/plugoid/0.1.0/quickstart.html)
- [`plugoid_demo`](https://github.com/tanguilp/plugoid_demo): a demo application using `Plugoid`

## Installation

```elixir
def deps do
  [
    {:plugoid, "~> 0.1.0"}
  ]
end
```

## When to use it

Possible uses are:
- when you entirely delegate user authentication to an external OpenID Connect Provider (OP)
- when you want to integrate with third-party providers ("social login"). Note that:
  - this library and the library it uses are very strict and might fail with some social login
  providers that don't strictly follows the standard
  - it has not been tested with any public OpenID Connect Provider (social login provider)
  - it does not support pure OAuth2 authentication providers

## Project status

The implementation of the standard is comprehsensive but as for all security related libraries,
care should be taken when assessing it. This library is not (yet?) widely used and has
received little scrutiny by other programmers or security specialists.

This project is also looking for contributors. Feel free to take a look at issues opened in the
following projects:
- [Plugoid issues](https://github.com/tanguilp/plugoid/issues)
- [OIDC issues](https://github.com/tanguilp/oidc/issues)
- [OAuth2TokenManager issues](https://github.com/tanguilp/oauth2_token_manager/issues)

## Protocol support

- [x] [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
  - [x] 3. Authentication
    - [x] authorization code flow:
      - [x] `"code"` response type
    - [x] implicit flow:
      - [x] `"id_token"` response type
      - [x] `"id_token token"` response type
    - [x] hybrid flow:
      - [x] `"code id_token"` response type
      - [x] `"code token"` response type
      - [x] `"code id_token token"` response type
  - [ ] 4. Initiating Login from a Third Party
  - [x] 5. Claims
    - [x] 5.3. UserInfo Endpoint (via
    [`OAuth2TokenManager`](https://github.com/tanguilp/oauth2_token_manager))
    - [x] 5.4. Requesting Claims using Scope Values
    - [x] 5.5. Requesting Claims using the "claims" Request Parameter, including special
    handling of:
      - `"acr"`
      - `"auth_time"`
  - [ ] 6. Passing Request Parameters as JWTs
  - [x] 9. Client Authentication (via
  [`TeslaOAuth2ClientAuth`](https://github.com/tanguilp/tesla_oauth2_client_auth))
    - [x] `"client_secret_basic"`
    - [x] `"client_secret_post"`
    - [x] `"client_secret_jwt"`
    - [x] `"private_key_jwt"`
    - [x] `"none"`
  - [x] 12. Using Refresh Tokens (via
    [`OAuth2TokenManager`](https://github.com/tanguilp/oauth2_token_manager))
- [x] [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [x] [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [x] [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [x] [RFC7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
