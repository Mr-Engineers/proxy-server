from fastapi.responses import JSONResponse


def error_response(status_code: int, error_type: str, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"type": error_type, "code": code, "message": message}},
    )
