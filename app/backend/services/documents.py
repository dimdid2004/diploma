import json

from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.core.aont import AontManager
from backend.db.database import Document, DocShard
from backend.services.s3 import get_s3_client


aont_manager = AontManager()


def reconstruct_document(doc: Document, db: Session) -> bytes:
    shards_db = (
        db.query(DocShard)
        .filter(DocShard.doc_id == doc.id, DocShard.version == doc.active_version)
        .all()
    )

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
            resp = s3.get_object(
                Bucket=shard_entry.node.bucket_name, Key=shard_entry.object_key
            )
            data = resp["Body"].read()
            collected_shards.append((shard_entry.shard_index, data))
        except Exception as error:
            print(f"Fetch error from node {shard_entry.node_id}: {error}")
            continue

    if len(collected_shards) < target_k:
        raise HTTPException(
            503,
            "Недостаточно фрагментов для восстановления. "
            f"Найдено {len(collected_shards)} из {target_k}",
        )

    try:
        if is_raw_mode:
            return collected_shards[0][1]
        return aont_manager.recover_and_decrypt(collected_shards, k, n, meta)
    except Exception as error:
        raise HTTPException(500, f"Ошибка восстановления: {error}")
