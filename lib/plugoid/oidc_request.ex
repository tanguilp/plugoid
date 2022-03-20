defmodule Plugoid.OIDCRequest do
  @moduledoc false

  @enforce_keys [:challenge, :initial_request_path]

  defstruct [
    :challenge,
    :initial_request_path,
    :initial_request_params
  ]

  @type t :: %__MODULE__{
          challenge: OIDC.Auth.Challenge.t(),
          initial_request_path: binary(),
          initial_request_params: Plug.Conn.query_params()
        }
end
