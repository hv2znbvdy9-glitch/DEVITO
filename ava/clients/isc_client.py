"""ISC (Identity Security Cloud) client for AVA."""

import json
from typing import Any, Dict, Optional

from ava.utils.exceptions import ValidationError


class WorkflowResult:
    """Result of a workflow test execution."""

    def __init__(
        self,
        workflow_id: str,
        status: str,
        output: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Initialize a workflow result."""
        self.workflow_id = workflow_id
        self.status = status
        self.output = output or {}
        self.error = error

    @property
    def succeeded(self) -> bool:
        """Return True if the workflow completed without errors."""
        return self.status == "completed" and self.error is None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result to a plain dictionary."""
        return {
            "workflow_id": self.workflow_id,
            "status": self.status,
            "output": self.output,
            "error": self.error,
        }


class ISCClient:
    """Client for interacting with Identity Security Cloud workflows.

    Parameters
    ----------
    tenant:
        The ISC tenant URL or identifier.
    read_only:
        When ``True`` the client operates in read-only mode and refuses to
        execute mutating operations such as :meth:`testWorkflow`.
    """

    def __init__(self, tenant: str = "", read_only: bool = False) -> None:
        """Initialise the ISC client."""
        self.tenant = tenant
        self.read_only = read_only

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def testWorkflow(
        self,
        workflow_id: str,
        payload: Optional[str] = None,
    ) -> WorkflowResult:
        """Test-execute a workflow and return the execution result.

        Parameters
        ----------
        workflow_id:
            Identifier of the workflow to run.
        payload:
            Optional JSON string with the input payload passed to the
            workflow.  When provided the string must be valid JSON and
            must represent a JSON object (``{…}``).

        Returns
        -------
        :class:`WorkflowResult`
            Execution result containing the workflow status and output.

        Raises
        ------
        :class:`~ava.utils.exceptions.ValidationError`
            If the client is in read-only mode, ``workflow_id`` is empty,
            or ``payload`` is not valid JSON / not a JSON object.
        """
        if self.read_only:
            raise ValidationError(
                "Cannot execute workflow: tenant is in read-only mode"
            )

        if not workflow_id or not workflow_id.strip():
            raise ValidationError("workflow_id cannot be empty")

        input_data: Dict[str, Any] = {}
        if payload is not None:
            input_data = self._parse_payload(payload)

        return self._execute_workflow(workflow_id.strip(), input_data)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_payload(payload: str) -> Dict[str, Any]:
        """Parse and validate a JSON payload string.

        Raises
        ------
        :class:`~ava.utils.exceptions.ValidationError`
            If the string is not valid JSON or does not represent an object.
        """
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Invalid JSON payload: {exc}") from exc

        if not isinstance(data, dict):
            raise ValidationError(
                "Payload must be a JSON object ({…}), "
                f"got {type(data).__name__}"
            )

        return data

    def _execute_workflow(
        self,
        workflow_id: str,
        input_data: Dict[str, Any],
    ) -> WorkflowResult:
        """Execute the workflow and return a :class:`WorkflowResult`.

        This default implementation performs a local dry-run that echoes the
        input back as output.  Real subclasses can override this method to
        call the actual ISC API.
        """
        output = {
            "workflow_id": workflow_id,
            "tenant": self.tenant,
            "input": input_data,
            "message": "Workflow executed successfully",
        }
        return WorkflowResult(
            workflow_id=workflow_id,
            status="completed",
            output=output,
        )
