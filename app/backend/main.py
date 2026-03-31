from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.routes import documents, nodes
from backend.core.exceptions import (
    DataIntegrityError,
    DocumentProcessingError,
    NotEnoughShardsError,
    ShardsNotFoundError,
    StorageNodeReadError,
)
from backend.db.database import init_db


def create_app() -> FastAPI:
    app = FastAPI(title="Secure Storage Control Panel")

    base_dir = Path(__file__).resolve().parent.parent
    static_dir = base_dir / "static"
    templates_dir = base_dir / "templates"

    static_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)

    init_db()

    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    templates = Jinja2Templates(directory=templates_dir)

    @app.exception_handler(ShardsNotFoundError)
    async def shards_not_found_handler(request: Request, exc: ShardsNotFoundError):
        return JSONResponse(
            status_code=404,
            content={"detail": "Фрагменты документа не найдены"},
        )

    @app.exception_handler(NotEnoughShardsError)
    async def not_enough_shards_handler(request: Request, exc: NotEnoughShardsError):
        return JSONResponse(
            status_code=503,
            content={"detail": "Недоступно требуемое число фрагментов"},
        )

    @app.exception_handler(DataIntegrityError)
    async def data_integrity_handler(request: Request, exc: DataIntegrityError):
        return JSONResponse(
            status_code=409,
            content={"detail": "Целостность данных нарушена"},
        )

    @app.exception_handler(StorageNodeReadError)
    async def storage_read_handler(request: Request, exc: StorageNodeReadError):
        return JSONResponse(
            status_code=503,
            content={"detail": "Не удалось получить данные из хранилищ"},
        )

    @app.exception_handler(DocumentProcessingError)
    async def document_processing_handler(request: Request, exc: DocumentProcessingError):
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка обработки документа"},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        print(f"Unhandled server error: {exc}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Внутренняя ошибка сервиса"},
        )

    @app.get("/", response_class=HTMLResponse)
    async def read_root(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="panel.html",
            context={},
        )

    app.include_router(nodes.router)
    app.include_router(documents.router)

    return app