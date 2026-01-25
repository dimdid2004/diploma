import json
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from sqlalchemy.orm import Session

from backend.db.database import Document, DocShard, StorageNode
from backend.dependencies import get_db
from backend.services.documents import reconstruct_document
from backend.services.files import detect_file_extension, detect_file_kind, normalize_title
from backend.services.s3 import delete_s3_object, get_s3_client

router = APIRouter(prefix="/api/documents", tags=["documents"])


@router.get("")
def get_documents(db: Session = Depends(get_db)):
    return db.query(Document).order_by(Document.last_modified.desc()).all()


@router.post("")
async def upload_document(
    file: UploadFile = File(...),
    nodes: str = Form(...),
    k: int = Form(...),
    title: str | None = Form(None),
    db: Session = Depends(get_db),
):
    normalized_title = normalize_title(file.filename, title)
    existing_doc = db.query(Document).filter(Document.title == normalized_title).first()
    if existing_doc:
        raise HTTPException(
            status_code=409,
            detail=f"Файл с именем '{normalized_title}' уже существует.",
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Нельзя загружать пустые файлы")

    node_ids = json.loads(nodes)
    n = len(node_ids)

    if k > n:
        raise HTTPException(400, "K не может быть больше N")

    doc = Document(
        title=normalized_title,
        content_type=file.content_type,
        file_extension=detect_file_extension(file.filename),
        file_kind=detect_file_kind(file.filename, file.content_type),
        size=len(content),
        active_version=1,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    is_raw_mode = n == 1

    if is_raw_mode:
        shards = [content]
        meta = {"mode": "raw"}
    else:
        try:
            from backend.services.documents import aont_manager

            shards, meta = aont_manager.encrypt_and_disperse(content, k, n)
            meta["mode"] = "aont"
        except Exception as error:
            db.delete(doc)
            db.commit()
            raise HTTPException(500, f"Encryption error: {error}")

    version = 1
    for i, shard_data in enumerate(shards):
        node_id = node_ids[i]
        node = db.query(StorageNode).filter(StorageNode.id == node_id).first()

        if not node or not node.is_active:
            continue

        object_key = f"{doc.id}/v{version}/shard-{i+1:02d}of{n:02d}.bin"

        try:
            s3 = get_s3_client(node)
            s3.put_object(Bucket=node.bucket_name, Key=object_key, Body=shard_data)

            shard_entry = DocShard(
                doc_id=doc.id,
                version=version,
                shard_index=i,
                node_id=node.id,
                object_key=object_key,
                k_param=k,
                n_param=n,
                meta_json=json.dumps(meta),
            )
            db.add(shard_entry)
        except Exception as error:
            print(f"Upload failed to node {node.id}: {error}")

    db.commit()
    return {"status": "ok", "doc_id": doc.id}


@router.post("/{doc_id}/update")
async def update_document(
    doc_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(404, "Документ не найден")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, "Нельзя загружать пустой файл")

    current_shards = (
        db.query(DocShard)
        .filter(DocShard.doc_id == doc_id, DocShard.version == doc.active_version)
        .all()
    )

    if not current_shards:
        raise HTTPException(500, "Целостность данных нарушена")

    current_shards.sort(key=lambda x: x.shard_index)

    k = current_shards[0].k_param
    n = current_shards[0].n_param
    node_ids = [s.node_id for s in current_shards]

    for shard in current_shards:
        if shard.node and shard.node.is_active:
            delete_s3_object(shard.node, shard.object_key)
        db.delete(shard)

    new_version = doc.active_version + 1
    is_raw_mode = n == 1

    if is_raw_mode:
        shards = [content]
        meta = {"mode": "raw"}
    else:
        from backend.services.documents import aont_manager

        shards, meta = aont_manager.encrypt_and_disperse(content, k, n)
        meta["mode"] = "aont"

    for i, shard_data in enumerate(shards):
        if i >= len(node_ids):
            break

        node_id = node_ids[i]
        node = db.query(StorageNode).filter(StorageNode.id == node_id).first()

        if not node or not node.is_active:
            continue

        object_key = f"{doc.id}/v{new_version}/shard-{i+1:02d}of{n:02d}.bin"

        try:
            s3 = get_s3_client(node)
            s3.put_object(Bucket=node.bucket_name, Key=object_key, Body=shard_data)

            shard_entry = DocShard(
                doc_id=doc.id,
                version=new_version,
                shard_index=i,
                node_id=node.id,
                object_key=object_key,
                k_param=k,
                n_param=n,
                meta_json=json.dumps(meta),
            )
            db.add(shard_entry)
        except Exception as error:
            print(f"Error update upload: {error}")

    doc.active_version = new_version
    doc.last_modified = datetime.now()
    doc.size = len(content)
    doc.content_type = file.content_type
    doc.file_extension = detect_file_extension(file.filename)
    doc.file_kind = detect_file_kind(file.filename, file.content_type)

    db.commit()
    return {"status": "updated", "version": new_version}


@router.get("/{doc_id}/download")
def download_document(doc_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(404)
    original_data = reconstruct_document(doc, db)

    filename_encoded = quote(doc.title)

    return Response(
        content=original_data,
        media_type=doc.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}",
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.get("/{doc_id}/view")
def view_document(doc_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(404)

    original_data = reconstruct_document(doc, db)

    return Response(
        content=original_data,
        media_type=doc.content_type or "application/octet-stream",
        headers={"Content-Disposition": "inline"},
    )


@router.delete("/{doc_id}")
def delete_document(doc_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        return {"status": "not found"}

    all_shards = db.query(DocShard).filter(DocShard.doc_id == doc_id).all()
    for shard in all_shards:
        if shard.node and shard.node.is_active:
            delete_s3_object(shard.node, shard.object_key)

    db.delete(doc)
    db.commit()
    return {"status": "deleted"}
