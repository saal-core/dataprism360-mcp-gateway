# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/transports/test_streamable_rpc_permission_fallback.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the Streamable HTTP (/mcp) method permission check, _check_streamable_permission.

Policy Manager decides every /mcp method permission through the
HTTP_AUTH_CHECK_PERMISSION plugin. The check fails closed: a plugin denial,
no plugin decision, a plugin error and a missing user email all deny, and RBAC
never decides.
"""

# Standard
import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.transports.streamablehttp_transport import _check_streamable_permission


def _make_user_ctx(token_use: str = "session", teams=None) -> dict:
    """Build a user context dict as produced by the streamablehttp auth middleware."""
    ctx = {
        "email": "user@example.com",
        "is_admin": False,
        "is_authenticated": True,
        "teams": teams if teams is not None else ["team-abc123"],
    }
    if token_use is not None:
        ctx["token_use"] = token_use
    return ctx


@pytest.mark.asyncio
async def test_check_streamable_permission_grants_when_policy_manager_allows(policy_manager_decision):
    """A plugin grant allows the permission; the plugin gets the user and the permission."""
    user_ctx = _make_user_ctx()

    assert await _check_streamable_permission(user_context=user_ctx, permission="tools.execute") is True

    policy_manager_decision.assert_awaited_once_with(user_ctx, "tools.execute")


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", [False, None], ids=["plugin_denies", "no_plugin_decision"])
async def test_check_streamable_permission_denies_without_a_policy_manager_grant(policy_manager_decision, decision):
    """A plugin denial and no plugin decision both deny."""
    policy_manager_decision.return_value = decision

    assert await _check_streamable_permission(user_context=_make_user_ctx(), permission="tools.execute") is False


@pytest.mark.asyncio
async def test_check_streamable_permission_denies_admins_without_a_grant(policy_manager_decision):
    """Platform admins are decided by the plugin too."""
    policy_manager_decision.return_value = False
    admin_ctx = {**_make_user_ctx(), "is_admin": True, "teams": None}

    assert await _check_streamable_permission(user_context=admin_ctx, permission="admin.system_config") is False


@pytest.mark.asyncio
async def test_check_streamable_permission_denies_on_plugin_error(policy_manager_decision):
    """A plugin error (for example OPA unreachable) denies."""
    policy_manager_decision.side_effect = RuntimeError("OPA unreachable")

    assert await _check_streamable_permission(user_context=_make_user_ctx(), permission="tools.execute") is False


@pytest.mark.asyncio
async def test_check_streamable_permission_denies_a_user_without_email(policy_manager_decision):
    """A context with no user email is denied before the plugin is asked."""
    assert await _check_streamable_permission(user_context={"is_authenticated": True}, permission="tools.execute") is False

    policy_manager_decision.assert_not_awaited()


@pytest.mark.asyncio
async def test_servers_use_check_runs_for_server_scoped_route():
    """handle_streamable_http checks servers.use before it serves /servers/{id}/mcp."""
    # Third-Party
    import orjson

    # First-Party
    from mcpgateway.transports.streamablehttp_transport import SessionManagerWrapper, user_context_var

    class DummySessionManager:
        @contextlib.asynccontextmanager
        async def run(self):
            yield self

        async def handle_request(self, scope, receive, send_func):
            pass

    dummy_manager = DummySessionManager()
    dummy_manager.handle_request = AsyncMock()

    session_user_ctx = {
        "email": "dev@example.com",
        "teams": ["team-abc"],
        "is_admin": False,
        "is_authenticated": True,
        "token_use": "session",
    }

    mock_perm = AsyncMock(return_value=True)

    with patch("mcpgateway.transports.streamablehttp_transport.StreamableHTTPSessionManager", lambda **kwargs: dummy_manager):
        with patch("mcpgateway.transports.streamablehttp_transport.settings") as mock_settings:
            mock_settings.mcpgateway_session_affinity_enabled = False
            mock_settings.use_stateful_sessions = False
            wrapper = SessionManagerWrapper()
            await wrapper.initialize()

            token = user_context_var.set(session_user_ctx)
            try:
                with patch("mcpgateway.transports.streamablehttp_transport._check_streamable_permission", mock_perm):
                    path = "/servers/abc123def456/mcp"
                    scope = {
                        "type": "http",
                        "method": "POST",
                        "path": path,
                        "modified_path": path,
                        "scheme": "https",
                        "server": ("localhost", 4444),
                        "client": ("127.0.0.1", 0),
                        "headers": [(b"mcp-session-id", b"sess-1")],
                    }
                    body = orjson.dumps({"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": "1"})

                    async def receive():
                        return {"type": "http.request", "body": body}

                    sent = []

                    async def send(msg):
                        sent.append(msg)

                    await wrapper.handle_streamable_http(scope, receive, send)

                    mock_perm.assert_called_once()
                    assert mock_perm.call_args.kwargs == {"user_context": session_user_ctx, "permission": "servers.use"}
            finally:
                user_context_var.reset(token)
                await wrapper.shutdown()


@pytest.mark.asyncio
async def test_call_tool_raises_permission_error_when_session_token_denied():
    """call_tool must raise PermissionError when _check_streamable_permission returns False.

    Deny-path regression test: when Policy Manager denies the request, call_tool
    must raise PermissionError and not proceed to tool execution.
    """
    # First-Party
    from mcpgateway.transports.streamablehttp_transport import call_tool

    session_user_ctx = {
        "email": "user@example.com",
        "is_admin": False,
        "is_authenticated": True,
        "token_use": "session",
        "teams": ["team-abc123"],
    }

    with patch(
        "mcpgateway.transports.streamablehttp_transport._get_request_context_or_default",
        new=AsyncMock(return_value=(None, {}, session_user_ctx)),
    ):
        with patch(
            "mcpgateway.transports.streamablehttp_transport._should_enforce_streamable_rbac",
            return_value=True,
        ):
            with patch(
                "mcpgateway.transports.streamablehttp_transport._check_scoped_permission",
                return_value=True,
            ):
                with patch(
                    "mcpgateway.transports.streamablehttp_transport._check_streamable_permission",
                    new=AsyncMock(return_value=False),
                ):
                    with pytest.raises(PermissionError, match="Access denied"):
                        await call_tool("some_tool", {})
