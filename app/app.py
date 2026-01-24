import boto3
import json
import base64
import os
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from botocore.exceptions import ClientError
from typing import List, Dict

# Импорт Pure Python реализации
from core.aont import AontManager

app = FastAPI(title="Secure Storage AONT-RS (Pure Python)")

# Автоматическое создание папок
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

aont_manager = AontManager()

# Конфигурация узлов
STORAGE_NODES = [
    {'id': 0, 'name': 'Storage 1', 'endpoint': 'http://storage1:9000', 'access_key': 'admin', 'secret_key': 'password123', 'bucket': 'secure-data'},
    {'id': 1, 'name': 'Storage 2', 'endpoint': 'http://storage2:9000', 'access_key': 'admin', 'secret_key': 'password123', 'bucket': 'secure-data'},
    {'id': 2, 'name': 'Storage 3', 'endpoint': 'http://storage3:9000', 'access_key': 'admin', 'secret_key': 'password123', 'bucket': 'secure-data'},
    {'id': 3, 'name': 'Storage 4', 'endpoint': 'http://storage4:9000', 'access_key': 'admin', 'secret_key': 'password123', 'bucket': 'secure-data'},
]

def get_s3_client(node_id):
    config = next((n for n in STORAGE_NODES if n['id'] == node_id), None)
    if not config:
        raise ValueError("Unknown Node ID")
    return boto3.client(
        's3',
        endpoint_url=config['endpoint'],
        aws_access_key_id=config['access_key'],
        aws_secret_access_key=config['secret_key']
    )

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "nodes": STORAGE_NODES})

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    k: int = Form(...),
    n: int = Form(...),
    nodes: str = Form(...) 
):
    selected_nodes_ids = json.loads(nodes)
    
    if len(selected_nodes_ids) < n:
        raise HTTPException(status_code=400, detail=f"Нужно выбрать минимум {n} серверов")
    
    content = await file.read()
    
    # 1. Шифрование и разделение
    try:
        shards, meta = aont_manager.encrypt_and_disperse(content, k, n)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AONT Error: {str(e)}")

    file_map = {
        "filename": file.filename,
        "k": k,
        "n": n,
        "meta": meta,
        "fragments": []
    }

    # 2. Распределение (Round-Robin)
    for i, shard_data in enumerate(shards):
        target_node_id = selected_nodes_ids[i % len(selected_nodes_ids)]
        node_config = next(n for n in STORAGE_NODES if n['id'] == target_node_id)
        s3 = get_s3_client(target_node_id)
        
        object_name = f"{file.filename}.v1.part{i}"
        
        try:
            try:
                s3.head_bucket(Bucket=node_config['bucket'])
            except ClientError:
                s3.create_bucket(Bucket=node_config['bucket'])

            s3.put_object(Bucket=node_config['bucket'], Key=object_name, Body=shard_data)
            
            file_map["fragments"].append({
                "shard_index": i,
                "node_id": target_node_id,
                "object_key": object_name
            })
        except Exception as e:
            print(f"Error uploading to node {target_node_id}: {e}")
            raise HTTPException(status_code=502, detail=f"Storage Node {target_node_id} failed")

    return {"status": "success", "file_map": file_map}

@app.post("/download")
async def download_file(request: Request):
    """
    Принимает JSON с File Map, скачивает фрагменты, восстанавливает файл
    и возвращает его как скачиваемый поток (Attachment).
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
        
    file_map = data.get("file_map")
    
    if not file_map:
        raise HTTPException(status_code=400, detail="File Map required")

    k = int(file_map['k'])
    n = int(file_map['n'])
    meta = file_map['meta']
    fragments_info = file_map['fragments']

    collected_shards = []

    # Скачиваем доступные части
    for frag in fragments_info:
        # Оптимизация: если уже собрали K частей, прерываем цикл
        if len(collected_shards) >= k:
            break

        node_id = frag['node_id']
        node_config = next((n for n in STORAGE_NODES if n['id'] == node_id), None)
        
        try:
            s3 = get_s3_client(node_id)
            response = s3.get_object(Bucket=node_config['bucket'], Key=frag['object_key'])
            shard_data = response['Body'].read()
            collected_shards.append((frag['shard_index'], shard_data))
        except Exception as e:
            print(f"Node {node_id} unavailable or file missing: {e}")
            continue

    if len(collected_shards) < k:
        raise HTTPException(status_code=404, detail=f"Found only {len(collected_shards)}/{k} fragments. Recovery impossible.")

    # Восстановление
    try:
        original_data = aont_manager.recover_and_decrypt(collected_shards, k, n, meta)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Recovery failed: {str(e)}")

    # Возвращаем бинарный файл для скачивания браузером
    # filename кодируется в latin-1 для заголовков, либо просто отдаем как есть (для кириллицы может потребоваться quote)
    safe_filename = file_map['filename'] # В реальном продакшене лучше использовать urllib.parse.quote
    
    return Response(
        content=original_data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )