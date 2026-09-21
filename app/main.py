from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from app.core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Kalikiri Backend",
    description="E-commerce learning application - FastAPI backend",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    raw_errors = exc.errors()

    messages = []
    for err in raw_errors:
        msg = err.get("msg", "")
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, ") :]
        loc = err.get("loc", [])
        if loc and len(loc) > 1 and "Field required" in msg:
            field = str(loc[-1])
            msg = f"{field}: {msg}"
        messages.append(msg)
    detail = messages[0] if len(messages) == 1 else "; ".join(messages)
    return JSONResponse(status_code=422, content={"detail": detail})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI!"}


# Include routers
from app.routers.auth import router as auth_router  # noqa: E402

app.include_router(auth_router)
