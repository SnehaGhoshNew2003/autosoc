# api/middleware/error_middleware.py
#
# Global exception handler — catches unhandled exceptions and
# returns a structured JSON error instead of a raw 500 traceback.

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:
            logger.exception(f"Unhandled error on {request.method} {request.url.path}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "detail": str(exc),
                },
            )