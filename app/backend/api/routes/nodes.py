from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import CurrentUser
from backend.core.authz import authorize, build_request_context, build_subject
from backend.db.database import StorageNode
from backend.dependencies import get_current_user, get_db
from backend.services.s3 import check_node_connection

router = APIRouter(prefix="/api/nodes", tags=["nodes"])


def _node_resource(node: StorageNode | None = None) -> dict:
    if node is None:
        return {"type": "storage_nodes"}

    return {
        "type": "storage_node",
        "id": node.id,
        "is_active": node.is_active,
        "bucket_name": node.bucket_name,
    }


@router.get("")
def get_nodes(
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    authorize(
        subject=build_subject(user),
        action="nodes:list",
        resource=_node_resource(),
        request_context=build_request_context(request),
    )

    return db.query(StorageNode).all()


@router.post("")
def add_node(
    request: Request,
    ip: str = Form(...),
    port: str = Form(...),
    access_key: str = Form(...),
    secret_key: str = Form(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    authorize(
        subject=build_subject(user),
        action="nodes:create",
        resource=_node_resource(),
        request_context=build_request_context(request),
    )

    existing = (
        db.query(StorageNode)
        .filter(StorageNode.ip == ip, StorageNode.port == port)
        .first()
    )
    if existing:
        raise HTTPException(400, "Такой узел уже существует")

    node = StorageNode(
        ip=ip,
        port=port,
        access_key=access_key,
        secret_key=secret_key,
        bucket_name="data",
        is_active=False,
    )
    node.is_active = check_node_connection(node)

    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@router.post("/{node_id}/check")
def check_node(
    node_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    node = db.query(StorageNode).filter(StorageNode.id == node_id).first()
    if not node:
        raise HTTPException(404)

    authorize(
        subject=build_subject(user),
        action="nodes:check",
        resource=_node_resource(node),
        request_context=build_request_context(request),
    )

    node.is_active = check_node_connection(node)
    db.commit()
    return {"id": node.id, "is_active": node.is_active}


@router.delete("/{node_id}")
def delete_node(
    node_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    node = db.query(StorageNode).filter(StorageNode.id == node_id).first()

    authorize(
        subject=build_subject(user),
        action="nodes:delete",
        resource=_node_resource(node),
        request_context=build_request_context(request),
    )

    if node:
        db.delete(node)
        db.commit()

    return {"status": "ok"}