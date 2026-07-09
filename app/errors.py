import structlog
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

logger = structlog.get_logger()


class NaesbGatewayError(Exception):
    """Base class for errors this gateway raises internally."""


class ConfigError(NaesbGatewayError):
    pass


async def _unhandled_exception_handler(request: Request, exc: Exception) -> PlainTextResponse:
    # Anything reaching here is a bug, not a protocol-level rejection -- those
    # are represented as a signed Receipt with HTTP 200, not an exception.
    logger.exception("unhandled_exception", path=request.url.path)
    return PlainTextResponse("internal server error", status_code=500)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(Exception, _unhandled_exception_handler)
