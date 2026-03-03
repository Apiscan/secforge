"""Tests for GraphQL security plugin."""

import json
import pytest
import respx
import httpx

from secforge.plugins.graphql.scanner import GraphQLPlugin
from secforge.models.target import TargetConfig, ScopeConfig
from secforge.models.enums import Severity, FindingStatus
from secforge.core.client import SecForgeClient


@pytest.fixture
def target():
    return TargetConfig(
        url="https://api.example.com",
        scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
    )


MOCK_SCHEMA_RESPONSE = json.dumps({
    "data": {
        "__schema": {
            "types": [
                {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}]},
                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "users", "type": {"name": "User", "kind": "OBJECT"}}]},
            ]
        }
    }
})

MOCK_TYPENAME_RESPONSE = json.dumps({"data": {"__typename": "Query"}})


@pytest.mark.asyncio
async def test_introspection_enabled(target):
    """Server with introspection enabled should produce MEDIUM finding."""
    plugin = GraphQLPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False) as mock:
        # GraphQL endpoint discovery
        mock.post("/graphql").mock(return_value=httpx.Response(
            200,
            json={"data": {"__typename": "Query"}},
        ))
        # Override: return schema for introspection query
        def gql_handler(request):
            body = request.content.decode()
            if "__schema" in body:
                return httpx.Response(200, text=MOCK_SCHEMA_RESPONSE)
            if "__typename" in body:
                return httpx.Response(200, text=MOCK_TYPENAME_RESPONSE)
            if "usr" in body:  # typo probe for suggestions
                return httpx.Response(200, json={"errors": [{"message": "field not found"}]})
            return httpx.Response(200, json={"data": {}})

        mock.post("/graphql").mock(side_effect=gql_handler)
        mock.get("/graphql").mock(return_value=httpx.Response(
            200, json={"data": {"__typename": "Query"}}
        ))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    introspection_findings = [f for f in findings if "Introspection" in f.title]
    assert introspection_findings, f"Should detect introspection. Got: {[f.title for f in findings]}"
    assert introspection_findings[0].severity == Severity.MEDIUM
    assert introspection_findings[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_no_graphql_endpoint_returns_empty(target):
    """If no GraphQL endpoint found, return empty list."""
    plugin = GraphQLPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        # All GraphQL paths return 404
        for path in ["/graphql", "/api/graphql", "/api/v1/graphql", "/v1/graphql",
                     "/query", "/gql", "/graph"]:
            mock.post(path).mock(return_value=httpx.Response(404, text="Not Found"))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    assert findings == [], "No GraphQL endpoint = no findings"


@pytest.mark.asyncio
async def test_batching_detected(target):
    """Server accepting batched array queries should produce MEDIUM finding."""
    plugin = GraphQLPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False) as mock:
        def gql_handler(request):
            body = request.content.decode()
            if body.startswith("["):
                # Return array of results (batching accepted)
                return httpx.Response(200, json=[
                    {"data": {"__typename": "Query"}} for _ in range(10)
                ])
            return httpx.Response(200, json={"data": {"__typename": "Query"}})

        mock.post("/graphql").mock(side_effect=gql_handler)
        mock.get("/graphql").mock(return_value=httpx.Response(404))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    batch_findings = [f for f in findings if "Batching" in f.title]
    assert batch_findings, "Should detect batching"
    assert all(f.evidence for f in batch_findings)
