import hashlib
import math
import secrets
import struct
from itertools import combinations
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import curves, ellipticcurve


def _mod_inverse(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def _lagrange_interpolate_zero(xs: List[int], ys: List[int], modulus: int) -> int:
    if len(xs) != len(ys):
        raise ValueError("xs and ys length mismatch")
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x coordinates")

    result = 0
    k = len(xs)

    for i in range(k):
        xi, yi = xs[i], ys[i]
        numerator = 1
        denominator = 1

        for j in range(k):
            if i == j:
                continue
            xj = xs[j]
            numerator = (numerator * (-xj % modulus)) % modulus
            denominator = (denominator * (xi - xj)) % modulus

        li = numerator * _mod_inverse(denominator % modulus, modulus)
        result = (result + yi * li) % modulus

    return result

# Проверяемая схема Педерсена–Шамира на эллиптической кривой.
class PedersenShamirEC:
    def __init__(
        self,
        curve: curves.Curve,
        t: int,
        n: int,
        *,
        H: ellipticcurve.Point | None = None,
    ):
        self.curve_def = curve
        self.curve = curve.curve
        self.G = curve.generator
        self.order = curve.order
        self.t = t
        self.n = n

        if H is None:
            self._d = secrets.randbelow(self.order - 1) + 1
            self.H = self.G * self._d
        else:
            self._d = None
            self.H = H

    
    # Делит secret на n долей с порогом k    
    def share(
        self,
        secret: int,
    ) -> Tuple[List[Tuple[int, int, int]], List[ellipticcurve.Point], List[int], List[int]]:

        if not (0 <= secret < self.order):
            raise ValueError("secret must be in [0, order)")
        if self.t < 2:
            raise ValueError("threshold t must be >= 2")
        if self.n < self.t:
            raise ValueError("n must be >= t")

        a = [secret] + [secrets.randbelow(self.order) for _ in range(1, self.t)]
        b = [secrets.randbelow(self.order) for _ in range(self.t)]

        commitments = [
            self.G * a_j + self.H * b_j
            for a_j, b_j in zip(a, b)
        ]

        shares: List[Tuple[int, int, int]] = []
        for i in range(1, self.n + 1):
            x = i
            y = sum(a[j] * pow(x, j, self.order) for j in range(self.t)) % self.order
            z = sum(b[j] * pow(x, j, self.order) for j in range(self.t)) % self.order
            shares.append((x, y, z))

        return shares, commitments, a, b

    def verify_share(
        self,
        share: Tuple[int, int, int],
        commitments: List[ellipticcurve.Point],
    ) -> bool:
        x, y, z = share

        lhs = self.G * y + self.H * z

        rhs = None
        for j, Rj in enumerate(commitments):
            term = Rj * pow(x, j, self.order)
            rhs = term if rhs is None else rhs + term

        return lhs == rhs

    def reconstruct(self, subset: List[Tuple[int, int, int]]) -> int:
        if len(subset) < self.t:
            raise ValueError(f"Need at least {self.t} shares")
        xs = [x for x, _, _ in subset[: self.t]]
        ys = [y for _, y, _ in subset[: self.t]]
        return _lagrange_interpolate_zero(xs, ys, self.order)

 # основная логика алгоритма:
class AlgorithmsManager:
    PACKET_HEADER_FORMAT = ">II"   # x и длина фрагмента
    PACKET_HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)
    SCALAR_SIZE = 32
    GF_POLY = 0x11D

    def __init__(self, curve: curves.Curve = curves.SECP256k1):
        self.curve_def = curve
        self.order = curve.order

        # Таблицы для кодирования и восстановления фрагментов.
        self.gf_exp: List[int] = []
        self.gf_log: List[int] = []
        self.gf_mul_table: List[List[int]] = []
        self._init_gf_tables()

    # Public API

    def encrypt_and_disperse(self, data: bytes, k: int, n: int) -> Tuple[List[bytes], Dict]:
        if not data:
            raise ValueError("Empty input is not allowed")
        if k < 2:
            raise ValueError("k must be >= 2")
        if n < k:
            raise ValueError("n must be >= k")
        if n > 255:
            raise ValueError("n is too large for GF(256)-based coding")

        # Ключ - случайное число из поля кривой.
        secret_int = secrets.randbelow(self.order - 1) + 1
        aes_key = secret_int.to_bytes(self.SCALAR_SIZE, "big")

        # AES в режиме CTR.
        nonce = secrets.token_bytes(16)
        ciphertext = self._aes256_ctr_crypt(aes_key, nonce, data)

        # Хэш потом нужен для маскирования части y
        digest = hashlib.sha256(ciphertext).digest()

        # Делим шифртекст на фрагменты.
        cipher_shards = self._rs_encode_systematic(ciphertext, k, n)

        # Делим ключ
        ps = PedersenShamirEC(self.curve_def, t=k, n=n)
        shares, commitments, _, _ = ps.share(secret_int)
        
        packets: List[bytes] = []

        for shard_data, share in zip(cipher_shards, shares):
            x, y, z = share

            y_bytes = y.to_bytes(self.SCALAR_SIZE, "big")
            z_bytes = z.to_bytes(self.SCALAR_SIZE, "big")
            masked_y = self._xor_bytes(y_bytes, digest)

            packet = self._pack_packet(x, masked_y, z_bytes, shard_data)
            packets.append(packet)

        # данные, которые нужны при восстановлении.
        meta = {
            "threshold": k,
            "total_shares": n,
            "nonce_hex": nonce.hex(),
            "ciphertext_len": len(ciphertext),
            "ps_h": self._point_to_json(ps.H),
            "ps_commitments": [self._point_to_json(p) for p in commitments],
        }

        return packets, meta

    def recover_and_decrypt(
        self,
        shards_data: List[Tuple[int, bytes]],
        k: int,
        n: int,
        meta: Dict,
    ) -> bytes:
        if len(shards_data) < k:
            raise ValueError(f"Need at least {k} packets, got {len(shards_data)}")

        parsed_packets = []
        used_indexes = set()

        # Сначала пытаюсь разобрать все пакеты.
        for shard_index, raw_packet in shards_data:
            if shard_index in used_indexes:
                continue
            used_indexes.add(shard_index)

            try:
                x, masked_y, z, shard_data = self._unpack_packet(raw_packet)
            except Exception:
                continue

            parsed_packets.append({
                "shard_index": shard_index,
                "x": x,
                "masked_y": masked_y,
                "z": z,
                "cipher_shard": shard_data,
            })

        if len(parsed_packets) < k:
            raise ValueError(
                f"Not enough parsable packets after packet parsing: got {len(parsed_packets)}, need {k}"
            )

        # публичные параметры для проверки долей ключа
        H = self._point_from_json(meta["ps_h"])
        commitments = []
        for item in meta["ps_commitments"]:
            commitments.append(self._point_from_json(item))

        ps = PedersenShamirEC(self.curve_def, t=k, n=n, H=H)

        last_error = None

        # перебор сочетания по k пакетов
        for subset in combinations(parsed_packets, k):
            try:
                cipher_shards = []
                for packet in subset:
                    cipher_shards.append((packet["shard_index"], packet["cipher_shard"]))

                ciphertext = self._rs_decode_systematic(
                    shards_data=cipher_shards,
                    k=k,
                    n=n,
                    ciphertext_len=meta["ciphertext_len"],
                )

                digest = hashlib.sha256(ciphertext).digest()

                valid_shares = []
                invalid_indexes = []

                # проверка ключа.
                for packet in subset:
                    try:
                        y_bytes = self._xor_bytes(packet["masked_y"], digest)
                        y = int.from_bytes(y_bytes, "big")
                        z = int.from_bytes(packet["z"], "big")
                        share = (packet["x"], y, z)

                        if y >= self.order or z >= self.order:
                            invalid_indexes.append(packet["shard_index"])
                            continue

                        if ps.verify_share(share, commitments):
                            valid_shares.append(share)
                        else:
                            invalid_indexes.append(packet["shard_index"])
                    except Exception:
                        invalid_indexes.append(packet["shard_index"])

                if len(valid_shares) < k:
                    raise ValueError(
                        "Integrity check failed for candidate subset: "
                        f"valid={len(valid_shares)}, required={k}, invalid={invalid_indexes}"
                    )
                
                secret_int = ps.reconstruct(valid_shares[:k])
                aes_key = secret_int.to_bytes(self.SCALAR_SIZE, "big")
                nonce = bytes.fromhex(meta["nonce_hex"])

                plaintext = self._aes256_ctr_crypt(aes_key, nonce, ciphertext)
                return plaintext

            except Exception as exc:
                last_error = exc
                continue

        raise ValueError(
            "Recovery failed for all packet combinations. "
            f"Last error: {last_error}"
        )

    # AES

    def _aes256_ctr_crypt(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    # GF(256)

    def _init_gf_tables(self) -> None:
        exp = [0] * 512
        log = [0] * 256

        x = 1
        for i in range(255):
            exp[i] = x
            log[x] = i

            x = x << 1
            if x & 0x100:
                x = x ^ self.GF_POLY

        for i in range(255, 512):
            exp[i] = exp[i - 255]

        mul_table = []
        for a in range(256):
            row = []
            for b in range(256):
                if a == 0 or b == 0:
                    row.append(0)
                else:
                    row.append(exp[log[a] + log[b]])
            mul_table.append(row)

        self.gf_exp = exp
        self.gf_log = log
        self.gf_mul_table = mul_table

    def _gf_mul(self, a: int, b: int) -> int:
        return self.gf_mul_table[a][b]

    def _gf_inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("GF inverse of zero")
        return self.gf_exp[255 - self.gf_log[a]]

    # Erasure coding 

    def _rs_encode_systematic(self, data: bytes, k: int, n: int) -> List[bytes]:
        if not data:
            raise ValueError("Empty input is not allowed")
        if not (2 <= k <= n <= 255):
            raise ValueError("Require 2 <= k <= n <= 255 for GF(256)")

        # k равных частей.
        shard_len = math.ceil(len(data) / k)
        padded_len = shard_len * k
        padding_len = padded_len - len(data)
        padded_data = data + (b"\x00" * padding_len)

        data_shards = []
        for i in range(k):
            part = padded_data[i * shard_len:(i + 1) * shard_len]
            data_shards.append(part)

        if n == k:
            return data_shards

        # построение генераторной матрицы
        generator = []

        for i in range(k):
            row = [0] * k
            row[i] = 1
            generator.append(row)

        ys = list(range(k))
        xs = list(range(k, n))

        for x in xs:
            row = []
            for y in ys:
                denom = x ^ y
                if denom == 0:
                    raise ValueError("Invalid Cauchy parameters")
                row.append(self._gf_inv(denom))
            generator.append(row)

        parity_rows = generator[k:]
        parity_shards = []

        for row in parity_rows:
            out = bytearray(shard_len)

            for coeff, shard in zip(row, data_shards):
                if coeff == 0:
                    continue
                if coeff == 1:
                    for i in range(shard_len):
                        out[i] ^= shard[i]
                else:
                    mul_row = self.gf_mul_table[coeff]
                    for i in range(shard_len):
                        out[i] ^= mul_row[shard[i]]

            parity_shards.append(bytes(out))

        return data_shards + parity_shards

    def _rs_decode_systematic(
        self,
        shards_data: List[Tuple[int, bytes]],
        k: int,
        n: int,
        ciphertext_len: int,
    ) -> bytes:
        if not (2 <= k <= n <= 255):
            raise ValueError("Require 2 <= k <= n <= 255 for GF(256)")
        if len(shards_data) < k:
            raise ValueError(f"Need at least {k} shards")

        unique_shards = {}
        for index, shard in shards_data:
            if not (0 <= index < n):
                raise ValueError(f"Shard index out of range: {index}")
            if index not in unique_shards:
                unique_shards[index] = shard

        if len(unique_shards) < k:
            raise ValueError(f"Need at least {k} unique shards")

        selected = sorted(unique_shards.items(), key=lambda item: item[0])[:k]
        selected_indexes = []
        selected_shards = []

        for index, shard in selected:
            selected_indexes.append(index)
            selected_shards.append(shard)

        shard_len = len(selected_shards[0])
        for shard in selected_shards:
            if len(shard) != shard_len:
                raise ValueError("All provided shards must have the same length")

        if n == k:
            if selected_indexes != list(range(k)):
                raise ValueError("For n == k, all original data shards 0..k-1 are required")
            recovered_data_shards = selected_shards
        else:
            # Снова строю ту же матрицу.
            generator = []

            for i in range(k):
                row = [0] * k
                row[i] = 1
                generator.append(row)

            ys = list(range(k))
            xs = list(range(k, n))

            for x in xs:
                row = []
                for y in ys:
                    denom = x ^ y
                    if denom == 0:
                        raise ValueError("Invalid Cauchy parameters")
                    row.append(self._gf_inv(denom))
                generator.append(row)

            # Беру подматрицу по  полученным фрагментам
            matrix = []
            for idx in selected_indexes:
                matrix.append(generator[idx][:])

            size = len(matrix)
            aug = []

            for i in range(size):
                row = matrix[i][:] + [1 if i == j else 0 for j in range(size)]
                aug.append(row)

            for col in range(size):
                pivot = -1
                for row in range(col, size):
                    if aug[row][col] != 0:
                        pivot = row
                        break

                if pivot == -1:
                    raise ValueError("Matrix is not invertible over GF(256)")

                if pivot != col:
                    aug[col], aug[pivot] = aug[pivot], aug[col]

                pivot_val = aug[col][col]
                inv_pivot = self._gf_inv(pivot_val)

                for j in range(2 * size):
                    aug[col][j] = self._gf_mul(aug[col][j], inv_pivot)

                for row in range(size):
                    if row == col:
                        continue

                    factor = aug[row][col]
                    if factor == 0:
                        continue

                    for j in range(2 * size):
                        aug[row][j] ^= self._gf_mul(factor, aug[col][j])

            inverse = []
            for row in aug:
                inverse.append(row[size:])

            # обратная матрица умножается на пришедшие фрагменты.
            recovered_data_shards = []

            for row in inverse:
                out = bytearray(shard_len)

                for coeff, shard in zip(row, selected_shards):
                    if coeff == 0:
                        continue
                    if coeff == 1:
                        for i in range(shard_len):
                            out[i] ^= shard[i]
                    else:
                        mul_row = self.gf_mul_table[coeff]
                        for i in range(shard_len):
                            out[i] ^= mul_row[shard[i]]

                recovered_data_shards.append(bytes(out))

        recovered = b"".join(recovered_data_shards)
        return recovered[:ciphertext_len]

    # utils 
    def _pack_packet(self, x: int, masked_y: bytes, z: bytes, shard: bytes) -> bytes:
        if len(masked_y) != self.SCALAR_SIZE:
            raise ValueError("masked_y must be 32 bytes")
        if len(z) != self.SCALAR_SIZE:
            raise ValueError("z must be 32 bytes")

        header = struct.pack(self.PACKET_HEADER_FORMAT, x, len(shard))
        packet = header + masked_y + z + shard
        return packet

    def _unpack_packet(self, packet: bytes) -> Tuple[int, bytes, bytes, bytes]:
        min_size = self.PACKET_HEADER_SIZE + self.SCALAR_SIZE + self.SCALAR_SIZE
        if len(packet) < min_size:
            raise ValueError("Packet is too short")

        x, shard_len = struct.unpack(
            self.PACKET_HEADER_FORMAT,
            packet[:self.PACKET_HEADER_SIZE],
        )

        offset = self.PACKET_HEADER_SIZE
        masked_y = packet[offset: offset + self.SCALAR_SIZE]
        offset += self.SCALAR_SIZE

        z = packet[offset: offset + self.SCALAR_SIZE]
        offset += self.SCALAR_SIZE

        shard = packet[offset: offset + shard_len]
        if len(shard) != shard_len:
            raise ValueError("Packet shard length mismatch")

        return x, masked_y, z, shard

    def _point_to_json(self, point: ellipticcurve.Point) -> Dict[str, str]:
        return {
            "x": f"{int(point.x()):064x}",
            "y": f"{int(point.y()):064x}",
        }

    def _point_from_json(self, payload: Dict[str, str]) -> ellipticcurve.Point:
        x = int(payload["x"], 16)
        y = int(payload["y"], 16)
        return ellipticcurve.Point(
            self.curve_def.curve,
            x,
            y,
            self.curve_def.order,
        )

    def _xor_bytes(self, left: bytes, right: bytes) -> bytes:
        if len(left) != len(right):
            raise ValueError("XOR operands must have the same length")

        result = bytearray()
        for i in range(len(left)):
            result.append(left[i] ^ right[i])

        return bytes(result)