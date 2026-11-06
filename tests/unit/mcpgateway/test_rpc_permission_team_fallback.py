# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/test_rpc_permission_team_fallback.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the /rpc method permission check, _ensure_rpc_permission.

Policy Manager decides every /rpc method permission through the
HTTP_AUTH_CHECK_PERMISSION plugin. The check fails closed: a plugin denial,
no plugin decision and a missing user email all raise -32003, and RBAC never
decides. The token scope cap (Layer 1) still applies before the plugin.
"""

# Standard
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import pytest
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.main import _ensure_rpc_permission
from mcpgateway.validation.jsonrpc import JSONRPCError


def _make_session_user(email: str = "user@example.com", is_admin: bool = False) -> dict:
    """Build a minimal user context that mimics a session token (token_use='session')."""
    return {
        "email": email,
        "is_admin": is_admin,
        "token_use": "session",
        "token_teams": None,
    }


@pytest.mark.asyncio
async def test_ensure_rpc_permission_grants_when_policy_manager_allows(policy_manager_decision):
    """A plugin grant allows the method; the plugin gets the user and the permission."""
    user = _make_session_user()

    await _ensure_rpc_permission(user, MagicMock(spec=Session), "tools.execute", "tools/call")

    policy_manager_decision.assert_awaited_once()
    args, kwargs = policy_manager_decision.await_args
    assert args[0]["email"] == "user@example.com"
    assert args[1] == "tools.execute"
    assert kwargs["team_id"] is None


@pytest.mark.asyncio
async def test_ensure_rpc_permission_passes_the_token_team_to_policy_manager(policy_manager_decision):
    """A single-team API token names its team to the plugin."""
    user = {"email": "user@example.com", "is_admin": False, "token_use": "api", "token_teams": ["team-abc"], "team_id": "team-abc"}

    await _ensure_rpc_permission(user, MagicMock(spec=Session), "tools.execute", "tools/call")

    assert policy_manager_decision.await_args.kwargs["team_id"] == "team-abc"


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", [False, None], ids=["plugin_denies", "no_plugin_decision"])
async def test_ensure_rpc_permission_denies_without_a_policy_manager_grant(policy_manager_decision, decision):
    """A plugin denial and no plugin decision both deny; RBAC is never asked."""
    policy_manager_decision.return_value = decision
    rbac_checker = MagicMock()

    with patch("mcpgateway.main.PermissionChecker", rbac_checker):
        with pytest.raises(JSONRPCError) as exc_info:
            await _ensure_rpc_permission(_make_session_user(), MagicMock(spec=Session), "tools.execute", "tools/call")

    assert exc_info.value.code == -32003
    assert "Access denied" in exc_info.value.message
    rbac_checker.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("permission", ["tools.execute", "admin.system_config"])
async def test_ensure_rpc_permission_gives_admins_no_bypass(policy_manager_decision, permission):
    """Platform admins are decided by the plugin too, admin.system_config included."""
    policy_manager_decision.return_value = False
    user = {**_make_session_user(is_admin=True), "permission_is_admin": True}

    with pytest.raises(JSONRPCError) as exc_info:
        await _ensure_rpc_permission(user, MagicMock(spec=Session), permission, "logging/setLevel")

    assert exc_info.value.code == -32003
    policy_manager_decision.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_rpc_permission_denies_a_user_without_email(policy_manager_decision):
    """A context with no user email is denied before the plugin is asked."""
    user = {"email": "", "is_admin": False, "token_use": "session"}

    with patch("mcpgateway.main.get_user_email", return_value=""):
        with pytest.raises(JSONRPCError) as exc_info:
            await _ensure_rpc_permission(user, MagicMock(spec=Session), "tools.execute", "tools/call")

    assert exc_info.value.code == -32003
    policy_manager_decision.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_rpc_permission_token_scope_cap_blocks_at_layer1(policy_manager_decision):
    """Explicit scopes.permissions=['tools.read'] blocks tools.execute before the plugin is asked."""
    mock_request = MagicMock()
    mock_request.state._jwt_verified_payload = (
        None,
        {"scopes": {"permissions": ["tools.read"]}},
    )

    with pytest.raises(JSONRPCError) as exc_info:
        await _ensure_rpc_permission(_make_session_user(), MagicMock(spec=Session), "tools.execute", "tools/call", request=mock_request)

    assert exc_info.value.code == -32003
    assert "Access denied" in exc_info.value.message
    policy_manager_decision.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_rpc_permission_denies_on_plugin_error(policy_manager_decision):
    """A plugin error (for example OPA unreachable) denies with -32003."""
    policy_manager_decision.side_effect = RuntimeError("OPA unreachable")

    with pytest.raises(JSONRPCError) as exc_info:
        await _ensure_rpc_permission(_make_session_user(), MagicMock(spec=Session), "tools.execute", "tools/call")

    assert exc_info.value.code == -32003
