"""Bound request bodies before decoding JSON, including chunked submissions."""

import asyncio

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyLimitExceeded(Exception):
    pass


class RequestBodyLimit:
    def __init__(self, app: ASGIApp, maximum: int = 262144, deadline: float = 15) -> None:
        self.app, self.maximum, self.deadline = app, maximum, deadline

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        size = 0

        async def bounded_receive() -> Message:
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > self.maximum:
                raise BodyLimitExceeded()
            return message

        # FastAPI may turn receive exceptions into generic JSON parsing errors,
        # so collect a bounded body before its request decoding begins.
        chunks: list[bytes] = []
        try:
            async with asyncio.timeout(self.deadline):
                while True:
                    message = await bounded_receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunks.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
        except BodyLimitExceeded:
            await JSONResponse(
                {"detail": "Request body exceeds service size limit."}, status_code=413
            )(scope, receive, send)
            return
        except TimeoutError:
            await JSONResponse({"detail": "Request body deadline exceeded."}, status_code=408)(
                scope, receive, send
            )
            return
        body = b"".join(chunks)
        supplied = False

        async def replay() -> Message:
            nonlocal supplied
            if not supplied:
                supplied = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
