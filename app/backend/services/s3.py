import boto3
from botocore.exceptions import ClientError

from backend.db.database import StorageNode


def get_s3_client(node: StorageNode, timeout: int = 5):
    config = boto3.session.Config(
        signature_version="s3v4",
        connect_timeout=timeout,
        read_timeout=timeout,
        retries={"max_attempts": 1},
    )
    return boto3.client(
        "s3",
        endpoint_url=node.get_endpoint(),
        aws_access_key_id=node.access_key,
        aws_secret_access_key=node.secret_key,
        config=config,
    )


def check_node_connection(node: StorageNode) -> bool:
    try:
        s3 = get_s3_client(node, timeout=3)
        s3.list_buckets()
        try:
            s3.head_bucket(Bucket=node.bucket_name)
        except ClientError as error:
            error_code = int(error.response["Error"]["Code"])
            if error_code == 404:
                s3.create_bucket(Bucket=node.bucket_name)
        return True
    except Exception as error:
        print(f"Node check failed: {error}")
        return False


def delete_s3_object(node: StorageNode, key: str) -> None:
    if not node.is_active:
        return
    try:
        s3 = get_s3_client(node)
        s3.delete_object(Bucket=node.bucket_name, Key=key)
    except Exception as error:
        print(f"Error delete S3: {error}")
