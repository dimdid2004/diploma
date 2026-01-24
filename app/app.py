import boto3
import json
import os
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException, Response, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from botocore.exceptions import ClientError
from typing import Optional
from pathlib import Path

from core.aont import AontManager
from core.database import SessionLocal, init_db, StorageNode, Document, DocShard

app = FastAPI(title="Secure Storage Control Panel")

os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

aont_manager = AontManager()

FILE_KIND_MAP = {
    "image": {"image/"},
    "pdf": {"application/pdf"},
    "text": {"text/"},
    "audio": {"audio/"},
    "video": {"video/"},
}

OFFICE_MIME_KINDS = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
    "application/msword": "document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "spreadsheet",
    "application/vnd.ms-excel": "spreadsheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "presentation",
    "application/vnd.ms-powerpoint": "presentation",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}

def detect_file_extension(filename: str) -> str:
    return Path(filename).suffix.lower().lstrip(".")

def detect_file_kind(filename: str, content_type: Optional[str]) -> str:
    extension = Path(filename).suffix.lower()
    if extension in ARCHIVE_EXTENSIONS:
        return "archive"

    if content_type:
        if content_type in OFFICE_MIME_KINDS:
            return OFFICE_MIME_KINDS[content_type]
        for kind, prefixes in FILE_KIND_MAP.items():
            for prefix in prefixes:
                if content_type.startswith(prefix):
                    return kind

    if extension in {".txt", ".md", ".json", ".csv", ".log"}:
        return "text"
    if extension in {".pdf"}:
        return "pdf"
    if extension in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}:
        return "image"
    if extension in {".mp3", ".wav", ".ogg", ".flac", ".m4a"}:
        return "audio"
    if extension in {".mp4", ".webm", ".mov", ".avi", ".mkv"}:
        return "video"
    if extension in {".doc", ".docx"}:
        return "document"
    if extension in {".xls", ".xlsx"}:
        return "spreadsheet"
    if extension in {".ppt", ".pptx"}:
        return "presentation"

    return "unknown"

def normalize_title(filename: str, title: Optional[str]) -> str:
    fallback = Path(filename).stem
    if not title:
        return fallback

    cleaned = title.strip()
    extension = Path(filename).suffix.lower()
    if extension and cleaned.lower().endswith(extension):
        cleaned = cleaned[: -len(extension)].rstrip()
    return cleaned or fallback


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_s3_client(node: StorageNode, timeout=5):
    # Обычный HTTP клиент
    config = boto3.session.Config(
        signature_version='s3v4',
        connect_timeout=timeout,
        read_timeout=timeout,
        retries={'max_attempts': 1}
    )
    return boto3.client(
        's3',
        endpoint_url=node.get_endpoint(),
        aws_access_key_id=node.access_key,
        aws_secret_access_key=node.secret_key,
        config=config
    )

def check_node_connection(node: StorageNode) -> bool:
    try:
        s3 = get_s3_client(node, timeout=3)
        s3.list_buckets()
        try:
            s3.head_bucket(Bucket=node.bucket_name)
        except ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 404:
                s3.create_bucket(Bucket=node.bucket_name)
        return True
    except Exception as e:
        print(f"Node check failed: {e}")
        return False

def delete_s3_object(node: StorageNode, key: str):
    if not node.is_active: return
    try:
        s3 = get_s3_client(node)
        s3.delete_object(Bucket=node.bucket_name, Key=key)
    except Exception as e:
        print(f"Error delete S3: {e}")

def reconstruct_document(doc: Document, db: Session) -> bytes:
    shards_db = db.query(DocShard).filter(
        DocShard.doc_id == doc.id,
        DocShard.version == doc.active_version
    ).all()

    if not shards_db:
        raise HTTPException(404, "Фрагменты не найдены")

    k = shards_db[0].k_param
    n = shards_db[0].n_param
    meta = json.loads(shards_db[0].meta_json)
    is_raw_mode = meta.get("mode") == "raw"
    target_k = 1 if is_raw_mode else k

    collected_shards = []

    for shard_entry in shards_db:
        if len(collected_shards) >= target_k:
            break

        if not shard_entry.node or not shard_entry.node.is_active:
            continue

        try:
            s3 = get_s3_client(shard_entry.node)
            resp = s3.get_object(Bucket=shard_entry.node.bucket_name, Key=shard_entry.object_key)
            data = resp['Body'].read()
            collected_shards.append((shard_entry.shard_index, data))
        except Exception as e:
            print(f"Fetch error from node {shard_entry.node_id}: {e}")
            continue

    if len(collected_shards) < target_k:
        raise HTTPException(503, f"Недостаточно фрагментов для восстановления. Найдено {len(collected_shards)} из {target_k}")

    try:
        if is_raw_mode:
            return collected_shards[0][1]
        return aont_manager.recover_and_decrypt(collected_shards, k, n, meta)
    except Exception as e:
        raise HTTPException(500, f"Ошибка восстановления: {e}")

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("panel.html", {"request": request})

@app.get("/api/nodes")
def get_nodes(db: Session = Depends(get_db)):
    return db.query(StorageNode).all()

@app.post("/api/nodes")
def add_node(
    ip: str = Form(...), port: str = Form(...),
    access_key: str = Form(...), secret_key: str = Form(...),
    db: Session = Depends(get_db)
):
    existing = db.query(StorageNode).filter(StorageNode.ip == ip, StorageNode.port == port).first()
    if existing:
        raise HTTPException(400, "Такой узел уже существует")
    
    node = StorageNode(
        ip=ip, port=port, access_key=access_key, secret_key=secret_key,
        bucket_name="data", is_active=False
    )
    node.is_active = check_node_connection(node)
    db.add(node)
    db.commit()
    db.refresh(node)
    return node

@app.post("/api/nodes/{node_id}/check")
def check_node(node_id: int, db: Session = Depends(get_db)):
    node = db.query(StorageNode).filter(StorageNode.id == node_id).first()
    if not node: raise HTTPException(404)
    node.is_active = check_node_connection(node)
    db.commit()
    return {"id": node.id, "is_active": node.is_active}

@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: int, db: Session = Depends(get_db)):
    node = db.query(StorageNode).filter(StorageNode.id == node_id).first()
    if node:
        db.delete(node)
        db.commit()
    return {"status": "ok"}

# --- API Documents ---

@app.get("/api/documents")
def get_documents(db: Session = Depends(get_db)):
    return db.query(Document).order_by(Document.last_modified.desc()).all()

@app.post("/api/documents")
async def upload_document(
    file: UploadFile = File(...),
    nodes: str = Form(...), 
    k: int = Form(...),
    title: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    normalized_title = normalize_title(file.filename, title)
    existing_doc = db.query(Document).filter(Document.title == normalized_title).first()
    if existing_doc:
        raise HTTPException(status_code=409, detail=f"Файл с именем '{normalized_title}' уже существует.")

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
        active_version=1
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    is_raw_mode = (n == 1)
    
    if is_raw_mode:
        shards = [content]
        meta = {"mode": "raw"}
    else:
        try:
            shards, meta = aont_manager.encrypt_and_disperse(content, k, n)
            meta["mode"] = "aont"
        except Exception as e:
            db.delete(doc)
            db.commit()
            raise HTTPException(500, f"Encryption error: {e}")

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
                meta_json=json.dumps(meta)
            )
            db.add(shard_entry)
        except Exception as e:
            print(f"Upload failed to node {node.id}: {e}")
            
    db.commit()
    return {"status": "ok", "doc_id": doc.id}

@app.post("/api/documents/{doc_id}/update")
async def update_document(
    doc_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc: raise HTTPException(404, "Документ не найден")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, "Нельзя загружать пустой файл")

    current_shards = db.query(DocShard).filter(
        DocShard.doc_id == doc_id, 
        DocShard.version == doc.active_version
    ).all()
    
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
    is_raw_mode = (n == 1)
    
    if is_raw_mode:
        shards = [content]
        meta = {"mode": "raw"}
    else:
        shards, meta = aont_manager.encrypt_and_disperse(content, k, n)
        meta["mode"] = "aont"

    for i, shard_data in enumerate(shards):
        if i >= len(node_ids): break 

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
                meta_json=json.dumps(meta)
            )
            db.add(shard_entry)
        except Exception as e:
            print(f"Error update upload: {e}")

    doc.active_version = new_version
    doc.last_modified = datetime.now()
    doc.size = len(content)
    doc.content_type = file.content_type
    doc.file_extension = detect_file_extension(file.filename)
    doc.file_kind = detect_file_kind(file.filename, file.content_type)
    
    db.commit()
    return {"status": "updated", "version": new_version}

@app.get("/api/documents/{doc_id}/download")
def download_document(doc_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc: raise HTTPException(404)
    original_data = reconstruct_document(doc, db)

    from urllib.parse import quote
    filename_encoded = quote(doc.title)
    
    return Response(
        content=original_data,
        media_type=doc.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )

@app.get("/api/documents/{doc_id}/view")
def view_document(doc_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc: raise HTTPException(404)

    original_data = reconstruct_document(doc, db)

    return Response(
        content=original_data,
        media_type=doc.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": "inline"
        }
    )

@app.delete("/api/documents/{doc_id}")
def delete_document(doc_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc: return {"status": "not found"}

    all_shards = db.query(DocShard).filter(DocShard.doc_id == doc_id).all()
    for shard in all_shards:
        if shard.node and shard.node.is_active:
            delete_s3_object(shard.node, shard.object_key)

    db.delete(doc)
    db.commit()
    return {"status": "deleted"}
