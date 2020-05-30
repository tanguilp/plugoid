defmodule PlugoidWeb.PreserveRequestParamsView do
  @moduledoc false

  use Phoenix.View, root: "lib/plugoid_web/templates"

  def request_data(conn) do
    %{
      method: conn.method,
      body_params: conn.body_params,
      query_params: URI.encode_query(conn.query_params)
    }
    |> Jason.encode!()
    |> Phoenix.HTML.javascript_escape()
    |> Phoenix.HTML.raw()
  end
end
