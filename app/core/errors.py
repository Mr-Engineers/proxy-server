from fastapi.responses import JSONResponse

AGENT_MESSAGES = {
    "blocked": "Action blocked by policy",
    "pending_approval": "Action requires human approval",
    "rate_limited": "Rate limit exceeded, retry later",
    "session_terminated": "Session terminated after repeated blocked actions",
    "invalid_arguments": "Request arguments are invalid",
}


def error_response(status_code: int, error_type: str, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"type": error_type, "code": code, "message": message}},
    )


def decision_response(
    status_code: int,
    status: str,
    decision_id: str,
    extra: dict | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Odpowiedź dla agenta (D10): ogólny kod + krótki komunikat + `decision_id`, bez uzasadnień."""
    message = AGENT_MESSAGES.get(status, status)
    content = {
        "status": status,
        "decision_id": decision_id,
        "message": message,
        **(extra or {}),
        "error": {"type": "policy_error", "code": status, "message": message},
    }
    return JSONResponse(status_code=status_code, content=content, headers={"X-Decision-Id": decision_id, **(headers or {})})
