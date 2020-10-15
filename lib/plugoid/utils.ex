defmodule Plugoid.Utils do
  @moduledoc false

  @spec server_metadata(Plugoid.opts()) :: %{optional(String.t()) => any()}
  def server_metadata(opts) do
    Oauth2MetadataUpdater.get_metadata(opts[:issuer], opts[:oauth2_metadata_updater_opts] || [])
    |> case do
      {:ok, loaded_server_metadata} ->
        Map.merge(loaded_server_metadata, opts[:server_metadata] || %{})

      {:error, _} ->
        opts[:server_metadata] || %{}
    end
  end

  @spec op_jwks(Plugoid.opts()) :: [JOSEUtils.JWKS.t()]
  def op_jwks(opts) do
    if opts[:jwks] do
      opts[:jwks]
    else
      jwks_uri =
        if opts[:jwks_uri] do
          opts[:jwks_uri]
        else
          Oauth2MetadataUpdater.get_metadata_value(
            opts[:issuer],
            "jwks_uri",
            opts[:oauth2_metadata_updater_opts] || []
          )
          |> case do
            {:ok, jwks_uri} ->
              jwks_uri

            {:error, reason} ->
              raise "Unable to retrieve JWKS URI (#{inspect(reason)})"
          end
        end

      case JWKSURIUpdater.get_keys(jwks_uri) do
        {:ok, jwks} ->
          jwks

        {:error, reason} ->
          raise "Unable to retrieve JWKS (#{inspect(reason)})"
      end
    end
  end

  @spec client_jwks(Plugoid.opts()) :: [JOSEUtils.JWKS.t()]
  def client_jwks(opts) do
    client_config = opts[:client_config_module].(opts[:client_id])

    cond do
      client_config["jwks"] ->
        client_config["jwks"]

      client_config["jwks_uri"] ->
        case JWKSURIUpdater.get_keys(client_config["jwks_uri"]) do
          {:ok, jwks} ->
            jwks

          {:error, reason} ->
            raise "Unable to retrieve JWKS (#{inspect(reason)})"
        end

      true ->
        []
    end
  end

  @spec error_view_from_conn(Plug.Conn.t()) :: module()
  def error_view_from_conn(conn) do
    case conn.private[:phoenix_endpoint] do
      nil ->
        raise "Could not determine error view module, no view set in `conn`"

      endpoint when is_atom(endpoint) ->
        base_module = endpoint |> Module.split() |> List.first()

        Module.concat(base_module, ErrorView)
    end
  end
end
