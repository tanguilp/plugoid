defmodule PlugoidWeb.LogoutView do
  @moduledoc false

  use Phoenix.View, root: "lib/plugoid_web/templates"

  def issuer(conn), do: conn.query_params["issuer"] || raise "missing issuer query param"

  def client_id(conn), do: conn.query_params["client_id"] || raise "missing client_id query param"

  #FIXME: delete if useless
  def origin(conn) do
    router = Phoenix.Controller.router_module(conn)
    helper_module = Module.concat(router, Helpers)
    endpoint_module = Phoenix.Controller.endpoint_module(conn)

    apply(helper_module, :url, [endpoint_module])
  end

  def target_origin(conn) do
    conn
    |> issuer()
    |> URI.parse()
    |> Map.put(:fragment, nil)
    |> Map.put(:host, nil)
    |> Map.put(:path, nil)
    |> Map.put(:port, nil)
    |> Map.put(:query, nil)
    |> Map.put(:userinfo, nil)
    |> URI.to_string()
  end
end
