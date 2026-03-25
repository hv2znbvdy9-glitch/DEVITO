"""Tests for ISCClient.testWorkflow()."""

import json

import pytest

from ava.clients.isc_client import ISCClient, WorkflowResult
from ava.utils.exceptions import ValidationError


@pytest.fixture
def client() -> ISCClient:
    """Return a default ISCClient for each test."""
    return ISCClient(tenant="test-tenant")


@pytest.fixture
def readonly_client() -> ISCClient:
    """Return a read-only ISCClient."""
    return ISCClient(tenant="test-tenant", read_only=True)


# ---------------------------------------------------------------------------
# WorkflowResult
# ---------------------------------------------------------------------------


def test_workflow_result_succeeded_when_completed_without_error() -> None:
    """A completed result with no error is considered successful."""
    result = WorkflowResult(workflow_id="wf-1", status="completed")
    assert result.succeeded is True


def test_workflow_result_not_succeeded_when_error_present() -> None:
    """A result carrying an error message is not considered successful."""
    result = WorkflowResult(workflow_id="wf-1", status="completed", error="something went wrong")
    assert result.succeeded is False


def test_workflow_result_not_succeeded_when_not_completed() -> None:
    """A result with a non-completed status is not considered successful."""
    result = WorkflowResult(workflow_id="wf-1", status="failed")
    assert result.succeeded is False


def test_workflow_result_to_dict() -> None:
    """WorkflowResult.to_dict() includes all expected keys."""
    result = WorkflowResult(
        workflow_id="wf-99",
        status="completed",
        output={"key": "value"},
        error=None,
    )
    d = result.to_dict()
    assert d["workflow_id"] == "wf-99"
    assert d["status"] == "completed"
    assert d["output"] == {"key": "value"}
    assert d["error"] is None


# ---------------------------------------------------------------------------
# ISCClient.testWorkflow — happy-path
# ---------------------------------------------------------------------------


def test_testWorkflow_returns_workflow_result(client: ISCClient) -> None:
    """testWorkflow() returns a WorkflowResult instance."""
    result = client.testWorkflow("wf-001")
    assert isinstance(result, WorkflowResult)


def test_testWorkflow_result_succeeded(client: ISCClient) -> None:
    """testWorkflow() returns a successful result for a valid workflow."""
    result = client.testWorkflow("wf-001")
    assert result.succeeded


def test_testWorkflow_result_contains_workflow_id(client: ISCClient) -> None:
    """testWorkflow() echoes back the workflow ID in the result."""
    result = client.testWorkflow("wf-xyz")
    assert result.workflow_id == "wf-xyz"


def test_testWorkflow_with_json_payload(client: ISCClient) -> None:
    """testWorkflow() accepts a valid JSON object payload."""
    payload = json.dumps({"key": "value", "count": 42})
    result = client.testWorkflow("wf-002", payload=payload)
    assert result.succeeded
    assert result.output["input"] == {"key": "value", "count": 42}


def test_testWorkflow_without_payload(client: ISCClient) -> None:
    """testWorkflow() works fine when no payload is supplied."""
    result = client.testWorkflow("wf-003")
    assert result.succeeded
    assert result.output["input"] == {}


def test_testWorkflow_strips_whitespace_from_workflow_id(client: ISCClient) -> None:
    """testWorkflow() strips surrounding whitespace from the workflow ID."""
    result = client.testWorkflow("  wf-trimmed  ")
    assert result.workflow_id == "wf-trimmed"


def test_testWorkflow_tenant_reflected_in_output(client: ISCClient) -> None:
    """testWorkflow() includes the tenant name in the output."""
    result = client.testWorkflow("wf-tenant")
    assert result.output["tenant"] == "test-tenant"


# ---------------------------------------------------------------------------
# ISCClient.testWorkflow — validation errors
# ---------------------------------------------------------------------------


def test_testWorkflow_raises_on_read_only(readonly_client: ISCClient) -> None:
    """testWorkflow() raises ValidationError when client is in read-only mode."""
    with pytest.raises(ValidationError, match="read-only"):
        readonly_client.testWorkflow("wf-001")


def test_testWorkflow_raises_on_empty_workflow_id(client: ISCClient) -> None:
    """testWorkflow() raises ValidationError for an empty workflow ID."""
    with pytest.raises(ValidationError, match="workflow_id cannot be empty"):
        client.testWorkflow("")


def test_testWorkflow_raises_on_whitespace_workflow_id(client: ISCClient) -> None:
    """testWorkflow() raises ValidationError for a whitespace-only workflow ID."""
    with pytest.raises(ValidationError, match="workflow_id cannot be empty"):
        client.testWorkflow("   ")


def test_testWorkflow_raises_on_invalid_json_payload(client: ISCClient) -> None:
    """testWorkflow() raises ValidationError when payload is not valid JSON."""
    with pytest.raises(ValidationError, match="Invalid JSON payload"):
        client.testWorkflow("wf-001", payload="not-json")


def test_testWorkflow_raises_on_json_array_payload(client: ISCClient) -> None:
    """testWorkflow() raises ValidationError when payload is a JSON array."""
    with pytest.raises(ValidationError, match="JSON object"):
        client.testWorkflow("wf-001", payload="[1, 2, 3]")


def test_testWorkflow_raises_on_json_string_payload(client: ISCClient) -> None:
    """testWorkflow() raises ValidationError when payload is a bare JSON string."""
    with pytest.raises(ValidationError, match="JSON object"):
        client.testWorkflow("wf-001", payload='"hello"')


def test_testWorkflow_raises_on_json_number_payload(client: ISCClient) -> None:
    """testWorkflow() raises ValidationError when payload is a bare JSON number."""
    with pytest.raises(ValidationError, match="JSON object"):
        client.testWorkflow("wf-001", payload="42")


# ---------------------------------------------------------------------------
# ISCClient construction
# ---------------------------------------------------------------------------


def test_isc_client_default_not_read_only() -> None:
    """ISCClient defaults to non-read-only mode."""
    c = ISCClient()
    assert c.read_only is False


def test_isc_client_read_only_flag() -> None:
    """ISCClient stores the read_only flag correctly."""
    c = ISCClient(read_only=True)
    assert c.read_only is True


def test_isc_client_stores_tenant() -> None:
    """ISCClient stores the tenant identifier."""
    c = ISCClient(tenant="my-tenant")
    assert c.tenant == "my-tenant"
