import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from reedsolo import RSCodec, ReedSolomonError

class AontManager:
    """
    Реализация AONT-RS на чистом Python (reedsolo).
    """

    def __init__(self):
        pass

    def _xor_bytes(self, b1: bytes, b2: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(b1, b2))

    def encrypt_and_disperse(self, data: bytes, k: int, n: int):
        # 1. Шифрование AES-GCM
        encryption_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # 2. AONT
        h = hashlib.sha256(nonce + ciphertext).digest()
        masked_key = self._xor_bytes(encryption_key, h)
        aont_package = masked_key + nonce + ciphertext

        # 3. RS Фрагментация
        # Используем RSCodec(n-k). Если n=k (порог=все), то избыточности 0.
        # Reedsolo нормально обрабатывает n-k=0 (просто копирует данные).
        
        # Выравнивание
        original_len = len(aont_package)
        padding_len = (k - (original_len % k)) % k
        padded_data = aont_package + (b'\x00' * padding_len)
        
        shards = [bytearray() for _ in range(n)]
        
        # Striping (нарезаем по K байт)
        chunk_size = k
        
        if n > k:
            rsc = RSCodec(n - k)
            for i in range(0, len(padded_data), chunk_size):
                chunk = padded_data[i : i + chunk_size]
                chunk_ba = bytearray(chunk)
                encoded_chunk = rsc.encode(chunk_ba) # Длина будет N
                
                for j in range(n):
                    shards[j].append(encoded_chunk[j])
        else:
            # Случай K=N (нет избыточности, просто разделение)
            # Reedsolo encode добавит 0 байт, просто вернет то же самое?
            # Нет, RSCodec(0) может вести себя странно. Лучше вручную разбить.
            for i in range(0, len(padded_data), chunk_size):
                chunk = padded_data[i : i + chunk_size]
                # Chunk имеет длину K. У нас N=K серверов.
                # Просто кладем по 1 байту на каждый сервер.
                for j in range(n):
                    if j < len(chunk):
                        shards[j].append(chunk[j])
                    else:
                        # Сюда не должны попасть, т.к. паддинг выровнен
                        pass

        shards_bytes = [bytes(s) for s in shards]
        
        meta = {
            'orig_size': original_len,
            'padding': padding_len
        }

        return shards_bytes, meta

    def recover_and_decrypt(self, shards_data: list, k: int, n: int, meta: dict) -> bytes:
        if len(shards_data) < k:
            raise ValueError(f"Need at least {k} shards")

        # Sort shards by index just in case
        shards_data.sort(key=lambda x: x[0])

        shard_len = len(shards_data[0][1])
        recovered_stream = bytearray()
        
        # Индексы, которые у нас есть
        available_indexes = {s[0] for s in shards_data}
        missing_indexes = [i for i in range(n) if i not in available_indexes]
        shard_map = {s[0]: bytearray(s[1]) for s in shards_data}

        # Случай K=N
        if n == k:
            # Просто склеиваем байты "вертикально"
            # Для каждого байта в шарде берем байты со всех шардов
            for i in range(shard_len):
                for j in range(n):
                    if j in available_indexes:
                         recovered_stream.append(shard_map[j][i])
        else:
            # Восстановление через RS
            rsc = RSCodec(n - k)
            for i in range(shard_len):
                block = bytearray(n)
                for idx in available_indexes:
                    block[idx] = shard_map[idx][i]
                
                try:
                    decoded_chunk, _, _ = rsc.decode(block, erase_pos=missing_indexes)
                    recovered_stream.extend(decoded_chunk)
                except ReedSolomonError as e:
                    raise ValueError("RS Decode failed") from e

        # Удаление паддинга
        orig_size = meta['orig_size']
        full_package = recovered_stream[:orig_size]

        if len(full_package) < 44:
             raise ValueError("Recovered data too short")

        masked_key = full_package[:32]
        nonce = full_package[32:44]
        ciphertext = full_package[44:]

        h = hashlib.sha256(nonce + ciphertext).digest()
        encryption_key = self._xor_bytes(masked_key, h)

        try:
            aesgcm = AESGCM(encryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError("Decryption failed (integrity check)") from e