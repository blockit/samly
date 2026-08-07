defmodule Samly.SPHandler do
  @moduledoc false

  require Logger
  import Plug.Conn
  alias Plug.Conn
  require Samly.Esaml
  alias Samly.{Assertion, Esaml, Helper, IdpData, State, Subject}

  import Samly.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 5, redirect: 3]

  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  def consume_signin_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{pre_session_create_pipeline: pipeline, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()

    with {:ok, assertion} <- decode_idp_auth_resp(sp, saml_encoding, saml_response),
         :ok <- validate_authresp(conn, assertion, relay_state),
         assertion = %Assertion{assertion | idp_id: idp_id},
         conn = conn |> put_private(:samly_assertion, assertion),
         {:halted, %Conn{halted: false} = conn} <- {:halted, pipethrough(conn, pipeline)} do
      updated_assertion = conn.private[:samly_assertion]
      computed = updated_assertion.computed
      assertion = %Assertion{assertion | computed: computed, idp_id: idp_id}

      nameid = assertion.subject.name
      assertion_key = {idp_id, nameid}
      conn = State.put_assertion(conn, assertion_key, assertion)
      target_url = auth_target_url(conn, assertion, relay_state)

      conn
      |> configure_session(renew: true)
      |> put_session("samly_assertion_key", assertion_key)
      |> redirect(302, target_url)
    else
      {:halted, conn} -> conn
      {:error, reason} -> handle_consume_error(conn, reason)
      _ -> handle_consume_error(conn, :access_denied)
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # Session-loss shaped failures: the browser lost or replaced the session state
  # between signin and consume (replayed response, second login tab, dropped
  # cookie). A fresh signin usually succeeds without the user re-entering
  # credentials because the IdP still holds a live SSO session.
  @recoverable_reasons [:invalid_relay_state, :invalid_idp_id, :invalid_target_url]

  # Marks a signin round-trip that was already auto-retried. It rides in the
  # RelayState, which the IdP echoes back to us, so the loop guard holds even
  # when our session cookie is the thing that's broken.
  @retry_marker "retry_"

  def retry_marker, do: @retry_marker

  def handle_consume_error(conn, reason) do
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()
    retried? = String.starts_with?(relay_state, @retry_marker)

    Logger.warning(
      "[Samly] signin consume failed reason=#{inspect(reason)} " <>
        "idp=#{conn.private[:samly_idp].id} retried=#{retried?}"
    )

    if reason in @recoverable_reasons and not retried? do
      redirect(conn, 302, signin_url(conn, true))
    else
      conn
      |> put_resp_header("content-type", "text/html")
      |> send_resp(403, error_page(signin_url(conn, false), reason))
    end
  end

  defp signin_url(conn, retry?) do
    %IdpData{id: idp_id, base_url: base_url} = conn.private[:samly_idp]

    base_url =
      base_url ||
        URI.to_string(%URI{
          scheme: Atom.to_string(conn.scheme),
          host: conn.host,
          port: conn.port,
          path: "/sso"
        })

    idp_segment =
      if Application.get_env(:samly, :idp_id_from) == :subdomain, do: "", else: "/#{idp_id}"

    "#{base_url}/auth/signin#{idp_segment}" <> if retry?, do: "?samly_retry=1", else: ""
  end

  defp error_page(signin_url, reason) do
    """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Sign-in problem</title>
        <style>
          body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                 background: #f8fafc; color: #0f172a; display: flex; align-items: center;
                 justify-content: center; min-height: 100vh; margin: 0; }
          .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
                  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08); max-width: 26rem;
                  padding: 2rem; text-align: center; }
          h1 { font-size: 1.25rem; margin: 0 0 0.75rem; }
          p { color: #475569; font-size: 0.9375rem; line-height: 1.5; margin: 0 0 1.5rem; }
          a.button { background: #0f172a; border-radius: 8px; color: #fff; display: inline-block;
                     font-size: 0.9375rem; padding: 0.625rem 1.25rem; text-decoration: none; }
          .reason { color: #94a3b8; font-size: 0.75rem; margin-top: 1.5rem; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>We couldn't complete your sign-in</h1>
          <p>
            This can happen if the sign-in page was refreshed or open in more than
            one tab, or if your browser blocked cookies during login. Signing in
            again usually fixes it.
          </p>
          <a class="button" href="#{signin_url}">Try signing in again</a>
          <div class="reason">Error code: #{reason}</div>
        </div>
      </body>
    </html>
    """
  end

  # esaml raises on malformed base64/XML rather than returning an error tuple;
  # without this a garbled IdP response turns into a 500 instead of the error page.
  defp decode_idp_auth_resp(sp, saml_encoding, saml_response) do
    Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response)
  rescue
    _ -> {:error, :malformed_response}
  end

  # IDP-initiated flow auth response
  @spec validate_authresp(Conn.t(), Assertion.t(), binary) :: :ok | {:error, atom}
  defp validate_authresp(conn, %{subject: %{in_response_to: ""}}, relay_state) do
    idp_data = conn.private[:samly_idp]

    if idp_data.allow_idp_initiated_flow do
      if idp_data.allowed_target_urls do
        if relay_state in idp_data.allowed_target_urls do
          :ok
        else
          {:error, :invalid_target_url}
        end
      else
        :ok
      end
    else
      {:error, :idp_first_flow_not_allowed}
    end
  end

  # SP-initiated flow auth response
  defp validate_authresp(conn, _assertion, relay_state) do
    %IdpData{id: idp_id} = conn.private[:samly_idp]
    rs_in_session = get_session(conn, "relay_state")
    idp_id_in_session = get_session(conn, "idp_id")
    url_in_session = get_session(conn, "target_url")

    cond do
      rs_in_session == nil || rs_in_session != relay_state ->
        {:error, :invalid_relay_state}

      idp_id_in_session == nil || idp_id_in_session != idp_id ->
        {:error, :invalid_idp_id}

      url_in_session == nil ->
        {:error, :invalid_target_url}

      true ->
        :ok
    end
  end

  defp pipethrough(conn, nil), do: conn

  defp pipethrough(conn, pipeline) do
    pipeline.call(conn, [])
  end

  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, ""), do: "/"
  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, url), do: url

  defp auth_target_url(conn, _assertion, _relay_state) do
    get_session(conn, "target_url") || "/"
  end

  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()

    with {:ok, _payload} <- Helper.decode_idp_signout_resp(sp, saml_encoding, saml_response),
         ^relay_state when relay_state != nil <- get_session(conn, "relay_state"),
         ^idp_id <- get_session(conn, "idp_id"),
         target_url when target_url != nil <- get_session(conn, "target_url") do
      conn
      |> configure_session(drop: true)
      |> redirect(302, target_url)
    else
      error -> conn |> send_resp(403, "invalid_request #{inspect(error)}")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # non-ui logout request from IDP
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_request = conn.body_params["SAMLRequest"]
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()

    with {:ok, payload} <- Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
      Esaml.esaml_logoutreq(name: nameid, issuer: _issuer) = payload
      assertion_key = {idp_id, nameid}

      {conn, return_status} =
        case State.get_assertion(conn, assertion_key) do
          %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} ->
            conn = State.delete_assertion(conn, assertion_key)
            {conn, :success}

          _ ->
            {conn, :denied}
        end

      {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, return_status)

      conn
      |> configure_session(drop: true)
      |> send_saml_request(idp_signout_url, idp.use_redirect_for_req, resp_xml_frag, relay_state)
    else
      error ->
        Logger.error("#{inspect(error)}")
        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, :denied)

        conn
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)
end
