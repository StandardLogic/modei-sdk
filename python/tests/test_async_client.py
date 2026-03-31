"""Comprehensive tests for the asynchronous AsyncModusClient."""

import json

import httpx
import pytest
import respx

from modus.async_client import AsyncModusClient
from modus.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ModusError,
    ValidationError,
)

BASE_URL = "https://modustrust.ai"
API_KEY = "mod_test_xxx"

pytestmark = pytest.mark.asyncio


# ======================================================================
# Authentication
# ======================================================================


class TestAuthentication:
    async def test_bearer_token_header(self, async_client, mock_api):
        route = mock_api.get("/api/gates").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_gates()
        assert route.calls[0].request.headers["authorization"] == f"Bearer {API_KEY}"

    async def test_content_type_header(self, async_client, mock_api):
        route = mock_api.get("/api/gates").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_gates()
        assert route.calls[0].request.headers["content-type"] == "application/json"


# ======================================================================
# Gates
# ======================================================================


class TestGates:
    async def test_list_gates(self, async_client, mock_api):
        body = [{"gate_id": "gate_test-1", "name": "Test Gate"}]
        route = mock_api.get("/api/gates").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_gates()
        assert result == body
        assert route.calls[0].request.method == "GET"

    async def test_get_gate(self, async_client, mock_api):
        body = {"gate_id": "gate_test-1", "name": "Test Gate"}
        route = mock_api.get("/api/gates/gate_test-1").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_gate("gate_test-1")
        assert result == body

    async def test_create_gate(self, async_client, mock_api):
        resp_body = {"gate_id": "gate_new", "name": "New Gate", "profile": "L1"}
        route = mock_api.post("/api/gates").mock(
            return_value=httpx.Response(201, json=resp_body)
        )
        result = await async_client.create_gate(
            name="New Gate", gate_id="gate_new", profile="L1"
        )
        assert result == resp_body
        req = route.calls[0].request
        assert req.method == "POST"
        req_body = json.loads(req.content)
        assert req_body["name"] == "New Gate"
        assert req_body["gate_id"] == "gate_new"
        assert req_body["profile"] == "L1"

    async def test_create_gate_with_optional_fields(self, async_client, mock_api):
        route = mock_api.post("/api/gates").mock(
            return_value=httpx.Response(201, json={"gate_id": "gate_opt"})
        )
        await async_client.create_gate(
            name="Optional",
            gate_id="gate_opt",
            description="A test gate",
            allow_self_issued=True,
        )
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["description"] == "A test gate"
        assert req_body["allow_self_issued"] is True

    async def test_update_gate(self, async_client, mock_api):
        route = mock_api.patch("/api/gates/gate_test-1").mock(
            return_value=httpx.Response(200, json={"gate_id": "gate_test-1"})
        )
        result = await async_client.update_gate("gate_test-1", name="Updated")
        assert result["gate_id"] == "gate_test-1"
        req = route.calls[0].request
        assert req.method == "PATCH"
        assert json.loads(req.content)["name"] == "Updated"

    async def test_delete_gate(self, async_client, mock_api):
        route = mock_api.delete("/api/gates/gate_test-1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        result = await async_client.delete_gate("gate_test-1")
        assert result == {"deleted": True}
        assert route.calls[0].request.method == "DELETE"


# ======================================================================
# Passports
# ======================================================================


class TestPassports:
    async def test_list_passports(self, async_client, mock_api):
        body = [{"passport_id": "pp_abc"}]
        route = mock_api.get("/api/gates/gate_test-1/passports").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_passports("gate_test-1")
        assert result == body

    async def test_get_passport(self, async_client, mock_api):
        body = {"passport_id": "pp_abc", "agent_id": "agent-1"}
        route = mock_api.get("/api/gates/gate_test-1/passports/pp_abc").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_passport("gate_test-1", "pp_abc")
        assert result == body

    async def test_issue_passport(self, async_client, mock_api):
        resp_body = {"passport_id": "pp_new"}
        route = mock_api.post("/api/gates/gate_test-1/passports").mock(
            return_value=httpx.Response(201, json=resp_body)
        )
        result = await async_client.issue_passport(
            "gate_test-1",
            agent_id="agent-1",
            permissions=["read", "write"],
        )
        assert result == resp_body
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["agent_id"] == "agent-1"
        assert req_body["permissions"] == ["read", "write"]

    async def test_issue_passport_with_all_options(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/passports").mock(
            return_value=httpx.Response(201, json={"passport_id": "pp_full"})
        )
        await async_client.issue_passport(
            "gate_test-1",
            agent_id="agent-2",
            permissions=["read"],
            agent_name="Test Agent",
            agent_public_key="ed25519:abc123",
            constraints={"core:cost:max_per_action": 100},
            expires_in_seconds=3600,
            expires_in="1h",
            metadata={"env": "test"},
        )
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["agent_name"] == "Test Agent"
        assert req_body["agent_public_key"] == "ed25519:abc123"
        assert req_body["constraints"] == {"core:cost:max_per_action": 100}
        assert req_body["expires_in_seconds"] == 3600
        assert req_body["metadata"] == {"env": "test"}

    async def test_revoke_passport(self, async_client, mock_api):
        route = mock_api.delete("/api/gates/gate_test-1/passports/pp_abc").mock(
            return_value=httpx.Response(200, json={"revoked": True})
        )
        result = await async_client.revoke_passport("gate_test-1", "pp_abc")
        assert result == {"revoked": True}
        assert route.calls[0].request.method == "DELETE"

    async def test_reissue_passport(self, async_client, mock_api):
        route = mock_api.post("/api/passports/pp_abc/reissue").mock(
            return_value=httpx.Response(200, json={"passport_id": "pp_abc", "catalog_version": 3})
        )
        result = await async_client.reissue_passport("pp_abc", accept_catalog_version=3)
        assert result["catalog_version"] == 3
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["accept_catalog_version"] == 3

    async def test_reissue_passport_no_version(self, async_client, mock_api):
        route = mock_api.post("/api/passports/pp_abc/reissue").mock(
            return_value=httpx.Response(200, json={"passport_id": "pp_abc"})
        )
        await async_client.reissue_passport("pp_abc")
        req_body = json.loads(route.calls[0].request.content)
        assert req_body == {}


# ======================================================================
# Attestations
# ======================================================================


class TestAttestations:
    async def test_list_attestations(self, async_client, mock_api):
        body = [{"attestation_id": "att_1"}]
        route = mock_api.get("/api/gates/gate_test-1/attestations").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_attestations("gate_test-1")
        assert result == body

    async def test_list_attestations_with_filters(self, async_client, mock_api):
        route = mock_api.get("/api/gates/gate_test-1/attestations").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_attestations(
            "gate_test-1",
            passport_id="pp_abc",
            agent_id="agent-1",
            permission="read",
            since="2024-01-01",
            limit=10,
        )
        url = route.calls[0].request.url
        assert url.params["passport_id"] == "pp_abc"
        assert url.params["agent_id"] == "agent-1"
        assert url.params["permission"] == "read"
        assert url.params["since"] == "2024-01-01"
        assert url.params["limit"] == "10"

    async def test_list_attestations_omits_none_params(self, async_client, mock_api):
        route = mock_api.get("/api/gates/gate_test-1/attestations").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_attestations("gate_test-1", passport_id="pp_abc")
        url = route.calls[0].request.url
        assert "passport_id" in dict(url.params)
        assert "agent_id" not in dict(url.params)

    async def test_record_attestation(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/attestations").mock(
            return_value=httpx.Response(201, json={"attestation_id": "att_new"})
        )
        result = await async_client.record_attestation(
            "gate_test-1",
            passport_id="pp_abc",
            action="read",
            decision="allow",
        )
        assert result["attestation_id"] == "att_new"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["passport_id"] == "pp_abc"
        assert req_body["decision"] == "allow"


# ======================================================================
# Permission Catalog
# ======================================================================


class TestCatalogs:
    async def test_get_catalog(self, async_client, mock_api):
        body = {"permissions": [{"key": "read"}]}
        route = mock_api.get("/api/gates/gate_test-1/catalog").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_catalog("gate_test-1")
        assert result == body

    async def test_create_catalog(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/catalog").mock(
            return_value=httpx.Response(200, json={"status": "saved"})
        )
        result = await async_client.create_catalog(
            "gate_test-1",
            permissions=[{"key": "read"}, {"key": "write"}],
        )
        assert result["status"] == "saved"
        req_body = json.loads(route.calls[0].request.content)
        assert len(req_body["permissions"]) == 2

    async def test_publish_catalog(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/catalog/publish").mock(
            return_value=httpx.Response(200, json={"version": 1})
        )
        result = await async_client.publish_catalog(
            "gate_test-1",
            change_summary="Initial publish",
            effective_at="2024-06-01T00:00:00Z",
        )
        assert result["version"] == 1
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["change_summary"] == "Initial publish"

    async def test_publish_catalog_minimal(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/catalog/publish").mock(
            return_value=httpx.Response(200, json={"version": 2})
        )
        await async_client.publish_catalog("gate_test-1")
        req_body = json.loads(route.calls[0].request.content)
        assert req_body == {}

    async def test_list_catalog_versions(self, async_client, mock_api):
        body = [{"version": 1}, {"version": 2}]
        route = mock_api.get("/api/gates/gate_test-1/catalog/versions").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_catalog_versions("gate_test-1")
        assert len(result) == 2

    async def test_get_catalog_version(self, async_client, mock_api):
        body = {"version": 1, "permissions": [{"key": "read"}]}
        route = mock_api.get("/api/gates/gate_test-1/catalog/1").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_catalog_version("gate_test-1", 1)
        assert result["version"] == 1

    async def test_get_catalog_impact(self, async_client, mock_api):
        body = {"affected_passports": 3}
        route = mock_api.get("/api/gates/gate_test-1/catalog/impact").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_catalog_impact("gate_test-1")
        assert result["affected_passports"] == 3


# ======================================================================
# Gate Check (Authorization)
# ======================================================================


class TestGateCheck:
    async def test_check_gate(self, async_client, mock_api):
        resp = {"decision": "allow", "reason": "permitted"}
        route = mock_api.post("/api/gates/gate_test-1/check").mock(
            return_value=httpx.Response(200, json=resp)
        )
        result = await async_client.check_gate(
            "gate_test-1", action="read", passport_id="pp_abc"
        )
        assert result["decision"] == "allow"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["action"] == "read"
        assert req_body["passport_id"] == "pp_abc"

    async def test_check_gate_minimal(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/check").mock(
            return_value=httpx.Response(200, json={"decision": "deny"})
        )
        await async_client.check_gate("gate_test-1", action="write")
        req_body = json.loads(route.calls[0].request.content)
        assert req_body == {"action": "write"}

    async def test_check_gate_with_target(self, async_client, mock_api):
        route = mock_api.post("/api/gates/gate_test-1/check").mock(
            return_value=httpx.Response(200, json={"decision": "allow"})
        )
        await async_client.check_gate(
            "gate_test-1", action="read", target="/docs/secret"
        )
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["target"] == "/docs/secret"

    async def test_authorize_dry_run(self, async_client, mock_api):
        resp = {"decision": "allow", "constraints_satisfied": True}
        route = mock_api.post("/api/authorize/dry-run").mock(
            return_value=httpx.Response(200, json=resp)
        )
        result = await async_client.authorize_dry_run(
            gate_id="gate_test-1",
            passport={"passport_id": "pp_abc", "permissions": ["read"]},
            requested_permission="read",
        )
        assert result["decision"] == "allow"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["gate_id"] == "gate_test-1"
        assert req_body["requested_permission"] == "read"
        assert "requested_constraints" not in req_body

    async def test_authorize_dry_run_with_constraints(self, async_client, mock_api):
        route = mock_api.post("/api/authorize/dry-run").mock(
            return_value=httpx.Response(200, json={"decision": "deny"})
        )
        await async_client.authorize_dry_run(
            gate_id="gate_test-1",
            passport={"passport_id": "pp_abc"},
            requested_permission="write",
            requested_constraints={"core:cost:max_per_action": 50},
        )
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["requested_constraints"] == {"core:cost:max_per_action": 50}


# ======================================================================
# Constraints
# ======================================================================


class TestConstraints:
    async def test_get_constraints(self, async_client, mock_api):
        body = {"core:rate:max_per_minute": 60}
        route = mock_api.get("/api/passports/pp_abc/constraints").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_constraints("pp_abc")
        assert result == body
        assert route.calls[0].request.method == "GET"

    async def test_set_constraints(self, async_client, mock_api):
        """set_constraints must use PUT."""
        constraints = {"core:rate:max_per_minute": 120}
        route = mock_api.put("/api/passports/pp_abc/constraints").mock(
            return_value=httpx.Response(200, json={"updated": True})
        )
        result = await async_client.set_constraints("pp_abc", constraints)
        assert result["updated"] is True
        req = route.calls[0].request
        assert req.method == "PUT"
        assert json.loads(req.content) == constraints

    async def test_list_constraint_types(self, async_client, mock_api):
        body = [{"type": "core:rate:max_per_minute"}]
        route = mock_api.get("/api/constraints/types").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_constraint_types()
        assert result == body

    async def test_list_constraint_types_with_category(self, async_client, mock_api):
        route = mock_api.get("/api/constraints/types").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_constraint_types(category="core")
        assert route.calls[0].request.url.params["category"] == "core"

    async def test_list_constraint_templates(self, async_client, mock_api):
        body = [{"slug": "read-only"}]
        route = mock_api.get("/api/constraint-templates").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_constraint_templates()
        assert result == body

    async def test_list_constraint_templates_with_category(self, async_client, mock_api):
        route = mock_api.get("/api/constraint-templates").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_constraint_templates(category="system")
        assert route.calls[0].request.url.params["category"] == "system"

    async def test_apply_constraint_template(self, async_client, mock_api):
        route = mock_api.post("/api/passports/pp_abc/constraints").mock(
            return_value=httpx.Response(200, json={"applied": True})
        )
        result = await async_client.apply_constraint_template("pp_abc", "read-only")
        assert result["applied"] is True
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["template_slug"] == "read-only"

    async def test_create_constraint_template(self, async_client, mock_api):
        route = mock_api.post("/api/constraint-templates").mock(
            return_value=httpx.Response(201, json={"slug": "custom-tpl"})
        )
        result = await async_client.create_constraint_template(
            slug="custom-tpl",
            name="Custom Template",
            constraints={"core:rate:max_per_minute": 10},
        )
        assert result["slug"] == "custom-tpl"


# ======================================================================
# Enforcement (CEL)
# ======================================================================


class TestEnforcement:
    async def test_enforce_action(self, async_client, mock_api):
        resp = {"decision": "allow", "attestation_id": "enf_1"}
        route = mock_api.post("/api/enforce").mock(
            return_value=httpx.Response(200, json=resp)
        )
        result = await async_client.enforce_action(
            passport_id="pp_abc",
            action="read",
            target="/docs/file.txt",
            cost_cents=5,
            metadata={"source": "test"},
        )
        assert result["decision"] == "allow"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["passport_id"] == "pp_abc"
        assert req_body["action"] == "read"
        assert req_body["target"] == "/docs/file.txt"
        assert req_body["cost_cents"] == 5

    async def test_enforce_action_minimal(self, async_client, mock_api):
        route = mock_api.post("/api/enforce").mock(
            return_value=httpx.Response(200, json={"decision": "deny"})
        )
        await async_client.enforce_action(passport_id="pp_abc", action="write")
        req_body = json.loads(route.calls[0].request.content)
        assert "target" not in req_body
        assert "cost_cents" not in req_body

    async def test_list_enforcement_attestations(self, async_client, mock_api):
        body = [{"id": "enf_1"}, {"id": "enf_2"}]
        route = mock_api.get("/api/passports/pp_abc/enforcement").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_enforcement_attestations("pp_abc")
        assert len(result) == 2

    async def test_list_enforcement_attestations_with_filters(self, async_client, mock_api):
        route = mock_api.get("/api/passports/pp_abc/enforcement").mock(
            return_value=httpx.Response(200, json=[])
        )
        await async_client.list_enforcement_attestations(
            "pp_abc", decision="allow", limit=5
        )
        url = route.calls[0].request.url
        assert url.params["decision"] == "allow"
        assert url.params["limit"] == "5"

    async def test_get_enforcement_attestation(self, async_client, mock_api):
        body = {"id": "enf_1", "decision": "allow"}
        route = mock_api.get("/api/enforcement/enf_1").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_enforcement_attestation("enf_1")
        assert result["id"] == "enf_1"
        assert route.calls[0].request.method == "GET"

    async def test_verify_enforcement_attestation(self, async_client, mock_api):
        """verify_enforcement_attestation must use POST, not GET."""
        body = {"valid": True, "signature_ok": True}
        route = mock_api.post("/api/enforcement/enf_1/verify").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.verify_enforcement_attestation("enf_1")
        assert result["valid"] is True
        assert route.calls[0].request.method == "POST"


# ======================================================================
# Anonymous Access
# ======================================================================


class TestAnonymousAccess:
    async def test_get_anonymous_policy(self, async_client, mock_api):
        body = {"enabled": False, "permissions": []}
        route = mock_api.get("/api/gates/gate_test-1/anonymous-policy").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_anonymous_policy("gate_test-1")
        assert result["enabled"] is False

    async def test_set_anonymous_policy(self, async_client, mock_api):
        """set_anonymous_policy must use PUT, not POST or PATCH."""
        route = mock_api.put("/api/gates/gate_test-1/anonymous-policy").mock(
            return_value=httpx.Response(200, json={"enabled": True})
        )
        result = await async_client.set_anonymous_policy(
            "gate_test-1", enabled=True, permissions=["read"]
        )
        assert result["enabled"] is True
        req = route.calls[0].request
        assert req.method == "PUT"
        req_body = json.loads(req.content)
        assert req_body["enabled"] is True
        assert req_body["permissions"] == ["read"]

    async def test_get_anonymous_log(self, async_client, mock_api):
        body = [{"timestamp": "2024-01-01T00:00:00Z", "action": "read"}]
        route = mock_api.get("/api/gates/gate_test-1/anonymous-log").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_anonymous_log("gate_test-1")
        assert len(result) == 1


# ======================================================================
# Cumulative State
# ======================================================================


class TestCumulativeState:
    async def test_get_cumulative_state(self, async_client, mock_api):
        body = {"total_cost_cents": 150, "request_count": 42}
        route = mock_api.get("/api/passports/pp_abc/state").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_cumulative_state("pp_abc")
        assert result["total_cost_cents"] == 150

    async def test_reset_cumulative_state(self, async_client, mock_api):
        route = mock_api.post("/api/passports/pp_abc/state/reset").mock(
            return_value=httpx.Response(200, json={"reset": True})
        )
        result = await async_client.reset_cumulative_state("pp_abc", window_type="daily")
        assert result["reset"] is True
        assert json.loads(route.calls[0].request.content)["window_type"] == "daily"

    async def test_reset_cumulative_state_no_window(self, async_client, mock_api):
        route = mock_api.post("/api/passports/pp_abc/state/reset").mock(
            return_value=httpx.Response(200, json={"reset": True})
        )
        await async_client.reset_cumulative_state("pp_abc")
        assert json.loads(route.calls[0].request.content) == {}


# ======================================================================
# Commerce: Consumption Attestations
# ======================================================================


class TestCommerceConsumption:
    async def test_issue_consumption_attestation(self, async_client, mock_api):
        resp = {"attestation_id": "ca_1"}
        route = mock_api.post("/api/consume").mock(
            return_value=httpx.Response(201, json=resp)
        )
        result = await async_client.issue_consumption_attestation(
            passport_id="pp_abc",
            gate_id="gate_test-1",
            action="translate",
            outcome="success",
            quantity=3,
        )
        assert result["attestation_id"] == "ca_1"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["passport_id"] == "pp_abc"
        assert req_body["gate_id"] == "gate_test-1"
        assert req_body["action"] == "translate"
        assert req_body["outcome"] == "success"
        assert req_body["quantity"] == 3

    async def test_issue_consumption_attestation_with_optional(self, async_client, mock_api):
        route = mock_api.post("/api/consume").mock(
            return_value=httpx.Response(201, json={"attestation_id": "ca_2"})
        )
        await async_client.issue_consumption_attestation(
            passport_id="pp_abc",
            gate_id="gate_test-1",
            action="translate",
            outcome="success",
            agent_pop={"sig": "abc"},
            request_payload_hash="sha256:req",
            response_payload_hash="sha256:resp",
            metadata={"model": "gpt-4"},
        )
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["agent_pop"] == {"sig": "abc"}
        assert req_body["request_payload_hash"] == "sha256:req"
        assert req_body["response_payload_hash"] == "sha256:resp"
        assert req_body["metadata"] == {"model": "gpt-4"}


# ======================================================================
# Commerce: Discovery
# ======================================================================


class TestCommerceDiscovery:
    async def test_discover_services(self, async_client, mock_api):
        resp = {"services": [{"gate_id": "gate_translate"}]}
        route = mock_api.get("/api/discover").mock(
            return_value=httpx.Response(200, json=resp)
        )
        result = await async_client.discover_services("translation")
        assert result["services"][0]["gate_id"] == "gate_translate"
        url = route.calls[0].request.url
        assert url.params["capability"] == "translation"
        assert url.params["limit"] == "20"
        assert url.params["offset"] == "0"

    async def test_discover_services_with_filters(self, async_client, mock_api):
        route = mock_api.get("/api/discover").mock(
            return_value=httpx.Response(200, json={"services": []})
        )
        await async_client.discover_services(
            "translation",
            max_price_cents=100,
            min_uptime_bp=9500,
            max_response_time_ms=200,
            pricing_model="per_request",
            sort="price_asc",
            limit=5,
            offset=10,
        )
        url = route.calls[0].request.url
        assert url.params["max_price_cents"] == "100"
        assert url.params["min_uptime_bp"] == "9500"
        assert url.params["pricing_model"] == "per_request"
        assert url.params["sort"] == "price_asc"


# ======================================================================
# Commerce: Settlement & Billing
# ======================================================================


class TestCommerceSettlement:
    async def test_generate_settlement(self, async_client, mock_api):
        resp = {"settlement_id": "stl_1", "total_cents": 500}
        route = mock_api.post("/api/billing").mock(
            return_value=httpx.Response(201, json=resp)
        )
        result = await async_client.generate_settlement(
            gate_id="gate_test-1",
            period_type="monthly",
            period_start="2024-01-01",
            period_end="2024-01-31",
        )
        assert result["settlement_id"] == "stl_1"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["gate_id"] == "gate_test-1"
        assert req_body["period_type"] == "monthly"
        assert "agent_id" not in req_body

    async def test_generate_settlement_with_agent(self, async_client, mock_api):
        route = mock_api.post("/api/billing").mock(
            return_value=httpx.Response(201, json={"settlement_id": "stl_2"})
        )
        await async_client.generate_settlement(
            gate_id="gate_test-1",
            period_type="daily",
            period_start="2024-06-01",
            period_end="2024-06-01",
            agent_id="agent-1",
        )
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["agent_id"] == "agent-1"

    async def test_list_settlements(self, async_client, mock_api):
        resp = {"settlements": [{"settlement_id": "stl_1"}]}
        route = mock_api.get("/api/billing").mock(
            return_value=httpx.Response(200, json=resp)
        )
        result = await async_client.list_settlements()
        assert result == resp
        url = route.calls[0].request.url
        assert url.params["limit"] == "20"
        assert url.params["offset"] == "0"

    async def test_list_settlements_with_filters(self, async_client, mock_api):
        route = mock_api.get("/api/billing").mock(
            return_value=httpx.Response(200, json={"settlements": []})
        )
        await async_client.list_settlements(
            gate_id="gate_test-1",
            status="pending",
            from_date="2024-01-01",
            to_date="2024-12-31",
        )
        url = route.calls[0].request.url
        assert url.params["gate_id"] == "gate_test-1"
        assert url.params["status"] == "pending"
        assert url.params["from"] == "2024-01-01"
        assert url.params["to"] == "2024-12-31"

    async def test_get_settlement(self, async_client, mock_api):
        body = {"settlement_id": "stl_1", "status": "paid"}
        route = mock_api.get("/api/billing/stl_1").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.get_settlement("stl_1")
        assert result["status"] == "paid"

    async def test_update_settlement_status(self, async_client, mock_api):
        """update_settlement_status must use POST, not PATCH."""
        route = mock_api.post("/api/billing/stl_1/status").mock(
            return_value=httpx.Response(200, json={"status": "paid"})
        )
        result = await async_client.update_settlement_status("stl_1", "paid")
        assert result["status"] == "paid"
        req = route.calls[0].request
        assert req.method == "POST"
        assert json.loads(req.content) == {"status": "paid"}


# ======================================================================
# Commerce: SLA Compliance
# ======================================================================


class TestSLACompliance:
    async def test_get_sla_compliance(self, async_client, mock_api):
        resp = {"uptime_percent": 99.9}
        route = mock_api.get("/api/gates/gate_test-1/sla").mock(
            return_value=httpx.Response(200, json=resp)
        )
        result = await async_client.get_sla_compliance(
            "gate_test-1",
            period_start="2024-01-01",
            period_end="2024-01-31",
        )
        assert result["uptime_percent"] == 99.9
        url = route.calls[0].request.url
        assert url.params["period_start"] == "2024-01-01"
        assert url.params["period_end"] == "2024-01-31"

    async def test_get_sla_compliance_with_permission_key(self, async_client, mock_api):
        route = mock_api.get("/api/gates/gate_test-1/sla").mock(
            return_value=httpx.Response(200, json={})
        )
        await async_client.get_sla_compliance(
            "gate_test-1",
            period_start="2024-01-01",
            period_end="2024-01-31",
            permission_key="translate",
        )
        assert route.calls[0].request.url.params["permission_key"] == "translate"


# ======================================================================
# API Keys
# ======================================================================


class TestAPIKeys:
    async def test_list_api_keys(self, async_client, mock_api):
        body = [{"id": "key_1", "name": "Production"}]
        route = mock_api.get("/api/users/api-keys").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await async_client.list_api_keys()
        assert result == body

    async def test_create_api_key(self, async_client, mock_api):
        resp = {"id": "key_2", "key": "mod_live_new"}
        route = mock_api.post("/api/users/api-keys").mock(
            return_value=httpx.Response(201, json=resp)
        )
        result = await async_client.create_api_key(name="CI Key", scopes=["gates:read"])
        assert result["id"] == "key_2"
        req_body = json.loads(route.calls[0].request.content)
        assert req_body["name"] == "CI Key"
        assert req_body["scopes"] == ["gates:read"]

    async def test_create_api_key_no_scopes(self, async_client, mock_api):
        route = mock_api.post("/api/users/api-keys").mock(
            return_value=httpx.Response(201, json={"id": "key_3"})
        )
        await async_client.create_api_key(name="Default Key")
        req_body = json.loads(route.calls[0].request.content)
        assert req_body == {"name": "Default Key"}

    async def test_revoke_api_key(self, async_client, mock_api):
        route = mock_api.delete("/api/users/api-keys/key_1").mock(
            return_value=httpx.Response(200, json={"revoked": True})
        )
        result = await async_client.revoke_api_key("key_1")
        assert result["revoked"] is True
        assert route.calls[0].request.method == "DELETE"


# ======================================================================
# Error Handling
# ======================================================================


class TestErrorHandling:
    async def test_authentication_error_401(self, async_client, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(401, json={"message": "Invalid API key"})
        )
        with pytest.raises(AuthenticationError) as exc_info:
            await async_client.list_gates()
        assert exc_info.value.status_code == 401

    async def test_authorization_error_403(self, async_client, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(403, json={"message": "Insufficient scopes"})
        )
        with pytest.raises(AuthorizationError) as exc_info:
            await async_client.list_gates()
        assert exc_info.value.status_code == 403

    async def test_not_found_error_404(self, async_client, mock_api):
        mock_api.get("/api/gates/gate_nonexistent").mock(
            return_value=httpx.Response(404, json={"message": "Gate not found"})
        )
        with pytest.raises(NotFoundError) as exc_info:
            await async_client.get_gate("gate_nonexistent")
        assert exc_info.value.status_code == 404

    async def test_conflict_error_409(self, async_client, mock_api):
        mock_api.post("/api/gates").mock(
            return_value=httpx.Response(409, json={"message": "Gate already exists"})
        )
        with pytest.raises(ConflictError):
            await async_client.create_gate(name="Dup", gate_id="gate_dup")

    async def test_validation_error_400(self, async_client, mock_api):
        mock_api.post("/api/gates").mock(
            return_value=httpx.Response(400, json={"message": "Invalid format"})
        )
        with pytest.raises(ValidationError) as exc_info:
            await async_client.create_gate(name="Bad", gate_id="!!invalid!!")
        assert exc_info.value.status_code == 400

    async def test_validation_error_422(self, async_client, mock_api):
        mock_api.post("/api/gates").mock(
            return_value=httpx.Response(422, json={"message": "Missing field"})
        )
        with pytest.raises(ValidationError) as exc_info:
            await async_client.create_gate(name="", gate_id="gate_x")
        assert exc_info.value.status_code == 422

    async def test_rate_limit_error_429(self, async_client, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(
                429,
                json={"message": "Rate limit exceeded"},
                headers={"retry-after": "30"},
            )
        )
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.list_gates()
        assert exc_info.value.retry_after == 30.0

    async def test_rate_limit_error_no_retry_after(self, async_client, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(429, json={"message": "Too many requests"})
        )
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.list_gates()
        assert exc_info.value.retry_after is None

    async def test_server_error_500(self, async_client, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(500, json={"message": "Internal error"})
        )
        with pytest.raises(ModusError) as exc_info:
            await async_client.list_gates()
        assert exc_info.value.status_code == 500

    async def test_error_body_preserved(self, async_client, mock_api):
        error_body = {"message": "Not found", "details": {"gate_id": "gate_x"}}
        mock_api.get("/api/gates/gate_x").mock(
            return_value=httpx.Response(404, json=error_body)
        )
        with pytest.raises(NotFoundError) as exc_info:
            await async_client.get_gate("gate_x")
        assert exc_info.value.body == error_body

    async def test_non_json_error_response(self, async_client, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(502, text="Bad Gateway")
        )
        with pytest.raises(ModusError) as exc_info:
            await async_client.list_gates()
        assert exc_info.value.status_code == 502

    async def test_204_no_content(self, async_client, mock_api):
        mock_api.delete("/api/gates/gate_test-1").mock(
            return_value=httpx.Response(204)
        )
        result = await async_client.delete_gate("gate_test-1")
        assert result == {}


# ======================================================================
# Context Manager
# ======================================================================


class TestContextManager:
    async def test_async_context_manager(self, mock_api):
        mock_api.get("/api/gates").mock(
            return_value=httpx.Response(200, json=[])
        )
        async with AsyncModusClient(api_key=API_KEY, base_url=BASE_URL) as client:
            result = await client.list_gates()
            assert result == []
