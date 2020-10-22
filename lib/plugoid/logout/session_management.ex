defmodule Plugoid.Logout.SessionManagement do
  @moduledoc false

  @behaviour Plug

  alias Plugoid.{Logout, Utils}

  @hide_iframe_attrs "title='empty' style='display:none' width='0' height='0' tabindex='-1'"

  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> Phoenix.Controller.put_view(PlugoidWeb.LogoutView)
    |> Phoenix.Controller.render("check_session.html")
    |> Plug.Conn.halt()
  end

  @spec handle_authenticated_session(Plug.Conn.t(), Plugoid.opts()) :: Plug.Conn.t()
  def handle_authenticated_session(conn, opts) do
    server_metadata = Utils.server_metadata(opts)
    rp_iframe = Logout.check_session_path(conn)
    op_iframe = server_metadata["check_session_iframe"]

    if rp_iframe != nil and opts[:session_management] == true and is_binary(op_iframe) do
      Plug.Conn.register_before_send(
        conn, &add_iframes(&1, rp_iframe, op_iframe, opts)
      )
    else
      conn
    end
  end

  defp add_iframes(conn, rp_iframe, op_iframe, opts) do
    issuer_escaped = opts[:issuer] |> Phoenix.HTML.html_escape() |> elem(1) |> to_string()
    rp_iframe = rp_iframe_build_url(rp_iframe, opts)
    rp_iframe_id = "plugoid_session_management_iframe_rp_" <> issuer_escaped
    op_iframe_id = "plugoid_session_management_iframe_op_" <> issuer_escaped

    iframes = [
      "\n",
      "<iframe ",
      @hide_iframe_attrs,
      " id='",
      rp_iframe_id,
      "' src='",
      rp_iframe,
      "'></iframe>",
      "\n",
      "<iframe ",
      @hide_iframe_attrs,
      " id='",
      op_iframe_id,
      "' src='",
      op_iframe,
      "'></iframe>",
      "\n"
    ]

    %Plug.Conn{conn | resp_body: insert_iframes_in_body(conn.resp_body, iframes)}
  end

  defp rp_iframe_build_url(base_url, opts) do
    base_url
    |> URI.parse()
    |> Map.put(:query, URI.encode_query(Keyword.take(opts, [:issuer, :client_id])))
    |> URI.to_string()
    |> Phoenix.HTML.html_escape()
    |> elem(1)
    |> to_string()
  end

  defp insert_iframes_in_body(nil, _) do
    nil
  end

  defp insert_iframes_in_body(<<_::binary>> = content, iframes) do
    # closing tags accept blank chars after the tag name
    body_closing_tag_regex = ~r|(?<before>.*)(?<closing_tag></body[[:blank:]\n]*>)(?<following>.*)|s

    case Regex.named_captures(body_closing_tag_regex, content) do
      %{"before" => before, "closing_tag" => body_closing_tag, "following" => following} ->
        [before, iframes, body_closing_tag, following]

      nil ->
        content
    end
  end

  defp insert_iframes_in_body([last_elt], iframes) do
    insert_iframes_in_body(last_elt, iframes)
  end

  defp insert_iframes_in_body([h | t], iframes) do
    [h | insert_iframes_in_body(t, iframes)]
  end
end
