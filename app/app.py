import boto3
from fastapi import FastAPI
from botocore.exceptions import ClientError
from typing import Dict, Any

app = FastAPI(title="Secure Storage Gateway", version="0.1.0")

# Конфигурация подключений к хранилищам
STORAGE_NODES = [
    {'name': 'Storage 1', 'endpoint': 'http://storage1:9000', 'access_key': 'admin', 'secret_key': 'password123'},
    {'name': 'Storage 2', 'endpoint': 'http://storage2:9000', 'access_key': 'admin', 'secret_key': 'password123'},
    {'name': 'Storage 3', 'endpoint': 'http://storage3:9000', 'access_key': 'admin', 'secret_key': 'password123'},
    {'name': 'Storage 4', 'endpoint': 'http://storage4:9000', 'access_key': 'admin', 'secret_key': 'password123'},
]

def check_connection(node_config: Dict[str, str]) -> Dict[str, str]:
    """Проверка соединения с узлом"""
    try:
        s3 = boto3.client(
            's3',
            endpoint_url=node_config['endpoint'],
            aws_access_key_id=node_config['access_key'],
            aws_secret_access_key=node_config['secret_key']
        )
        s3.list_buckets()
        return {"status": "OK", "message": "Connection successful"}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

@app.get("/")
async def root():
    return {
        "message": "Secure Storage Gateway Prototype is running",
        "docs_url": "/docs"  # Подсказка, где искать документацию
    }

@app.get("/status")
async def get_status():
    """Проверяет доступность всех узлов хранения"""
    results = {}
    for node in STORAGE_NODES:
        results[node['name']] = check_connection(node)
    return results

@app.post("/init")
async def init_buckets():
    """Создает тестовые бакеты на всех узлах"""
    results = {}
    for node in STORAGE_NODES:
        try:
            s3 = boto3.client(
                's3',
                endpoint_url=node['endpoint'],
                aws_access_key_id=node['access_key'],
                aws_secret_access_key=node['secret_key']
            )
            bucket_name = "test-bucket"
            # В реальном коде стоит проверить existence, но для теста сойдет
            try:
                s3.create_bucket(Bucket=bucket_name)
                results[node['name']] = "Bucket 'test-bucket' created"
            except ClientError as e:
                # Если бакет уже есть или другая ошибка AWS
                results[node['name']] = f"AWS Error: {e}"
        except Exception as e:
            results[node['name']] = f"Connection Error: {str(e)}"
    return results