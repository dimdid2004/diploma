from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session

from backend.db.database import StorageNode
from backend.dependencies import get_db, require_roles
from backend.services.s3 import check_node_connection

from backend.core.auth import CurrentUser


router = APIRouter(prefix="/api/nodes", tags=["nodes"])


@router.get("")
def get_nodes(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_roles("editor", "admin")),
):
    return db.query(StorageNode).all()


@router.post("")
def add_node(
    ip: str = Form(...),
    port: str = Form(...),
    access_key: str = Form(...),
    secret_key: str = Form(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_roles("admin")),
):
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
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_roles("admin")),
):
    node = db.query(StorageNode).filter(StorageNode.id == node_id).first()
    if not node:
        raise HTTPException(404)
    node.is_active = check_node_connection(node)
    db.commit()
    return {"id": node.id, "is_active": node.is_active}


@router.delete("/{node_id}")
def delete_node(
    node_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_roles("admin")),
):
    node = db.query(StorageNode).filter(StorageNode.id == node_id).first()
    if node:
        db.delete(node)
        db.commit()
    return {"status": "ok"}
