"""OAuth 2.0 / RFC 7591 provider that maps onto the bearer-token model.

Claude Desktop's connector requires the OAuth 2.0 dynamic-client-registration
flow (RFC 8414/9728/7591). This provider translates that flow onto the
existing tokens.yml bearer scheme:

    Anthropic connector ──/register──▶ register_client (accept anything)
                        ──/authorize──▶ authorize() returns URL of our
                                        /auth/login HTML form, where the
                                        contractor pastes their bearer token.
                                        On submit we issue an auth code and
                                        redirect back to Anthropic.
                        ──/token─────▶ exchange_authorization_code returns
                                        an OAuthToken whose access_token IS
                                        the contractor's bearer.
                        ──/mcp───────▶ Authorization: Bearer <access_token>
                                        → load_access_token validates against
                                        tokens.yml; tool sees contractor name
                                        in the audit log.
"""

from __future__ import annotations

import time
from secrets import token_urlsafe
from typing import Callable, Optional

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

CODE_TTL_SECONDS = 600
LOGIN_TTL_SECONDS = 600


class MRCAuthorizationCode(AuthorizationCode):
    """AuthorizationCode that also carries the contractor's bearer forward
    to the token-exchange step. Stored in memory only."""

    user_token: str


class MRCOAuthProvider(
    OAuthAuthorizationServerProvider[MRCAuthorizationCode, RefreshToken, AccessToken]
):
    """Maps the OAuth 2.0 flow onto pre-issued bearer tokens in tokens.yml.

    Storage is in-memory: clients re-register via DCR after a restart;
    auth codes and login sessions are short-lived (10 min) so losing them
    is fine. tokens.yml on disk remains the source of truth.
    """

    def __init__(
        self,
        *,
        validate_token: Callable[[str], Optional[str]],
        login_url_for_session: Callable[[str], str],
    ):
        """
        validate_token: maps a bearer token → contractor name (or None).
        login_url_for_session: maps a login session_id → absolute URL of the
            HTML form where the contractor pastes their token.
        """
        self._validate_token = validate_token
        self._login_url_for_session = login_url_for_session
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, MRCAuthorizationCode] = {}
        self._login_sessions: dict[str, dict] = {}

    # -- Client (RFC 7591 Dynamic Client Registration) ---------------------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    async def get_client(
        self, client_id: str
    ) -> Optional[OAuthClientInformationFull]:
        return self._clients.get(client_id)

    # -- Authorization (3-legged via our /auth/login HTML page) ------------

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        session_id = token_urlsafe(24)
        self._login_sessions[session_id] = {
            "client_id": client.client_id,
            "params": params,
            "expires_at": time.time() + LOGIN_TTL_SECONDS,
        }
        return self._login_url_for_session(session_id)

    def consume_login_session(self, session_id: str) -> Optional[dict]:
        """Single-use lookup of an in-flight login session.

        Called by the /auth/login POST handler. Returns the stored
        {client_id, params} or None if expired/missing."""
        session = self._login_sessions.pop(session_id, None)
        if session is None:
            return None
        if time.time() > session["expires_at"]:
            return None
        return session

    def peek_login_session(self, session_id: str) -> Optional[dict]:
        """Non-consuming check used by the GET handler (so a re-render after
        an invalid token doesn't burn the session)."""
        session = self._login_sessions.get(session_id)
        if session is None:
            return None
        if time.time() > session["expires_at"]:
            self._login_sessions.pop(session_id, None)
            return None
        return session

    def issue_code(
        self,
        *,
        client_id: str,
        params: AuthorizationParams,
        user_token: str,
    ) -> str:
        code = token_urlsafe(32)
        self._codes[code] = MRCAuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=time.time() + CODE_TTL_SECONDS,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            user_token=user_token,
        )
        return code

    # -- Token exchange ----------------------------------------------------

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> Optional[MRCAuthorizationCode]:
        code = self._codes.get(authorization_code)
        if code is None:
            return None
        if code.client_id != client.client_id:
            return None
        if time.time() > code.expires_at:
            self._codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: MRCAuthorizationCode,
    ) -> OAuthToken:
        # Single-use: discard the code on exchange.
        self._codes.pop(authorization_code.code, None)
        # The contractor's bearer is the access token. Anthropic stores
        # this opaquely; subsequent requests Authorization: Bearer it.
        return OAuthToken(
            access_token=authorization_code.user_token,
            token_type="Bearer",
            expires_in=None,
            scope=None,
            refresh_token=None,
        )

    # -- Access token validation ------------------------------------------

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        contractor = self._validate_token(token)
        if contractor is None:
            return None
        return AccessToken(
            token=token,
            client_id="",
            scopes=[],
            expires_at=None,
            resource=None,
        )

    # -- Refresh tokens (not issued in this implementation) ---------------

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> Optional[RefreshToken]:
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise NotImplementedError("refresh tokens not supported")

    # -- Revocation -------------------------------------------------------

    async def revoke_token(self, token) -> None:
        # Tokens are revoked by editing /etc/mrc-refresh-mcp/tokens.yml on
        # the bastion. OAuth-side revocation is a no-op — load_access_token
        # will fail naturally on the next request after the file is edited.
        return None
