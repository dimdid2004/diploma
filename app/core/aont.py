import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from reedsolo import RSCodec, ReedSolomonError

class AontManager:
    """
    Реализация AONT-RS на чистом Python (без C-библиотек).
    Использует библиотеку reedsolo для математики Галуа.
    """

    def __init__(self):
        pass

    def _xor_bytes(self, b1: bytes, b2: bytes) -> bytes:
        """Побитовый XOR"""
        return bytes(x ^ y for x, y in zip(b1, b2))

    def encrypt_and_disperse(self, data: bytes, k: int, n: int):
        """
        1. Шифрование AES-GCM
        2. AONT преобразование
        3. Разделение на N частей через RS (Pure Python)
        """
        # --- Этап 1: Шифрование (AES-256) ---
        encryption_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # --- Этап 2: AONT (Скрытие ключа) ---
        # Hash(Ciphertext + Nonce)
        h = hashlib.sha256(nonce + ciphertext).digest()
        # Masked Key = Key XOR Hash
        masked_key = self._xor_bytes(encryption_key, h)
        # Итоговый пакет: [Masked Key (32)] + [Nonce (12)] + [Ciphertext]
        aont_package = masked_key + nonce + ciphertext

        # --- Этап 3: Фрагментация (Reed-Solomon Pure Python) ---
        # Библиотека reedsolo работает с блоками. Она добавляет (N-K) байт избыточности.
        
        rsc = RSCodec(n - k) # Создаем кодек, который добавляет (N-K) символов
        
        # 3.1 Паддинг (выравнивание) до кратности K
        original_len = len(aont_package)
        padding_len = (k - (original_len % k)) % k
        padded_data = aont_package + (b'\x00' * padding_len)

        # Подготовка буферов для N фрагментов
        shards = [bytearray() for _ in range(n)]

        # 3.2 Потоковое кодирование (Striping)
        chunk_size = k
        for i in range(0, len(padded_data), chunk_size):
            chunk = padded_data[i : i + chunk_size]
            # Превращаем в bytearray для reedsolo, если это bytes
            chunk_ba = bytearray(chunk)
            
            # encoded_chunk будет длиной N (K данных + N-K избыточность)
            encoded_chunk = rsc.encode(chunk_ba)
            
            # Раскидываем байты по шардам
            for j in range(n):
                shards[j].append(encoded_chunk[j])

        # Преобразуем в bytes для отправки
        shards_bytes = [bytes(s) for s in shards]

        meta = {
            'orig_size': original_len,
            'padding': padding_len
        }

        return shards_bytes, meta

    def recover_and_decrypt(self, shards_data: list, k: int, n: int, meta: dict) -> bytes:
        """
        Восстановление данных из фрагментов.
        shards_data: список кортежей [(shard_index, bytes_data), ...]
        """
        if len(shards_data) < k:
            raise ValueError(f"Need at least {k} shards, got {len(shards_data)}")

        # --- Этап 1: Восстановление RS ---
        rsc = RSCodec(n - k)
        
        # Нам нужно знать, какие индексы у нас есть
        available_indexes = {s[0] for s in shards_data}
        missing_indexes = [i for i in range(n) if i not in available_indexes]
        
        # Преобразуем входные данные в удобную структуру: dict {index: data}
        shard_map = {s[0]: bytearray(s[1]) for s in shards_data}
        
        # Определяем длину одного шарда
        shard_len = len(shards_data[0][1])
        
        recovered_stream = bytearray()
        
        # Проходим по байтам всех шардов синхронно
        for i in range(shard_len):
            # Собираем "вертикальный" блок длиной N
            block = bytearray(n)
            
            # Заполняем данными, которые есть
            for idx in available_indexes:
                block[idx] = shard_map[idx][i]
            
            # Декодируем
            # erase_pos сообщает алгоритму, какие позиции отсутствуют
            try:
                decoded_chunk, _, _ = rsc.decode(block, erase_pos=missing_indexes)
                # decoded_chunk будет длиной K (только данные, без кодов избыточности)
                recovered_stream.extend(decoded_chunk)
            except ReedSolomonError as e:
                raise ValueError("Corrupted shard data, cannot recover") from e

        # --- Этап 2: Удаление паддинга ---
        orig_size = meta['orig_size']
        full_package = recovered_stream[:orig_size]

        # --- Этап 3: Обратный AONT ---
        if len(full_package) < 44: # 32 (Key) + 12 (Nonce)
             raise ValueError("Recovered data is too short to be a valid AONT package")

        masked_key = full_package[:32]
        nonce = full_package[32:44]
        ciphertext = full_package[44:]

        h = hashlib.sha256(nonce + ciphertext).digest()
        encryption_key = self._xor_bytes(masked_key, h)

        # --- Этап 4: Расшифровка ---
        try:
            aesgcm = AESGCM(encryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            # Если тег аутентификации не совпал, значит ключ восстановлен неверно или данные повреждены
            raise ValueError("Integrity check failed. Data corruption or wrong key derived.") from e