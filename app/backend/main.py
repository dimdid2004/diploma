from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.routes import documents, nodes
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

    @app.get("/", response_class=HTMLResponse)
    async def read_root(request: Request):
        return templates.TemplateResponse("panel.html", {"request": request})

    app.include_router(nodes.router)
    app.include_router(documents.router)

    return app
