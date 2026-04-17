import hashlib
import math
import secrets
import struct
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import curves, ellipticcurve
from itertools import combinations

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


class PedersenShamirEC:
    """
    Проверяемая схема Педерсена–Шамира на эллиптической кривой.

    """

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

    def share(
        self,
        secret: int,
    ) -> Tuple[List[Tuple[int, int, int]], List[ellipticcurve.Point], List[int], List[int]]:
        """
        Делит secret на n долей с порогом t.
        """
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


class AlgorithmsManager:

    PACKET_HEADER_FORMAT = ">II"  # x, shard_length
    PACKET_HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)
    SCALAR_SIZE = 32

    def __init__(self, curve: curves.Curve = curves.SECP256k1):
        self.curve_def = curve
        self.order = curve.order
        self._gf256_init()
    
    # maths in GF(256)

    _GF_POLY = 0x11D
    _GF_EXP: List[int] | None = None
    _GF_LOG: List[int] | None = None
    _GF_MUL_TABLE: List[List[int]] | None = None

    def _gf256_init(self) -> None:
        if self.__class__._GF_EXP is not None:
            return

        exp = [0] * 512
        log = [0] * 256

        x = 1
        for i in range(255):
            exp[i] = x
            log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= self._GF_POLY

        for i in range(255, 512):
            exp[i] = exp[i - 255]

        mul_table = [[0] * 256 for _ in range(256)]
        for a in range(256):
            for b in range(256):
                if a == 0 or b == 0:
                    mul_table[a][b] = 0
                else:
                    mul_table[a][b] = exp[log[a] + log[b]]

        self.__class__._GF_EXP = exp
        self.__class__._GF_LOG = log
        self.__class__._GF_MUL_TABLE = mul_table

    @property
    def _gf_exp(self) -> List[int]:
        return self.__class__._GF_EXP  # type: ignore[return-value]

    @property
    def _gf_log(self) -> List[int]:
        return self.__class__._GF_LOG  # type: ignore[return-value]

    @property
    def _gf_mul_table(self) -> List[List[int]]:
        return self.__class__._GF_MUL_TABLE  # type: ignore[return-value]

    def _gf_mul(self, a: int, b: int) -> int:
        return self._gf_mul_table[a][b]

    def _gf_inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("GF inverse of zero")
        return self._gf_exp[255 - self._gf_log[a]]

    def _build_systematic_generator_matrix(self, k: int, n: int) -> List[List[int]]:
        """
        G = [I_k; P], где P — Cauchy-like MDS matrix над GF(256).
        """
        if not (2 <= k <= n <= 255):
            raise ValueError("Require 2 <= k <= n <= 255 for GF(256)")

        ys = list(range(k))
        xs = list(range(k, n))

        G: List[List[int]] = []

        for i in range(k):
            row = [0] * k
            row[i] = 1
            G.append(row)

        for x in xs:
            row = []
            for y in ys:
                denom = x ^ y
                if denom == 0:
                    raise ValueError("Invalid Cauchy parameters")
                row.append(self._gf_inv(denom))
            G.append(row)

        return G

    def _gf256_matrix_invert(self, matrix: List[List[int]]) -> List[List[int]]:
        size = len(matrix)
        if size == 0 or any(len(row) != size for row in matrix):
            raise ValueError("Matrix must be non-empty and square")

        aug = [row[:] + [1 if i == j else 0 for j in range(size)] for i, row in enumerate(matrix)]

        for col in range(size):
            pivot = None
            for row in range(col, size):
                if aug[row][col] != 0:
                    pivot = row
                    break

            if pivot is None:
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

        return [row[size:] for row in aug]

    def _apply_matrix_to_shards(
        self,
        matrix: List[List[int]],
        shards: List[bytes],
    ) -> List[bytes]:
        if not shards:
            raise ValueError("No shards provided")

        k = len(shards)
        shard_len = len(shards[0])

        if any(len(s) != shard_len for s in shards):
            raise ValueError("All shards must have the same length")

        if any(len(row) != k for row in matrix):
            raise ValueError("Matrix width must match number of shards")

        shard_views = [memoryview(s) for s in shards]
        out: List[bytes] = []

        for row in matrix:
            acc = bytearray(shard_len)

            for coeff, shard in zip(row, shard_views):
                if coeff == 0:
                    continue
                if coeff == 1:
                    for i in range(shard_len):
                        acc[i] ^= shard[i]
                else:
                    mul_row = self._gf_mul_table[coeff]
                    for i in range(shard_len):
                        acc[i] ^= mul_row[shard[i]]

            out.append(bytes(acc))

        return out

    # ---------- Public API ----------

    def encrypt_and_disperse(self, data: bytes, k: int, n: int) -> Tuple[List[bytes], Dict]:
        if not data:
            raise ValueError("Empty input is not allowed")
        if k < 2:
            raise ValueError("k must be >= 2")
        if n < k:
            raise ValueError("n must be >= k")
       
        if n > 255:
            raise ValueError("n is too large for GF(256)-based erasure coding")

        # 1) Генерация AES-256 ключа как скаляра в поле кривой
        secret_int = secrets.randbelow(self.order - 1) + 1
        aes_key = secret_int.to_bytes(self.SCALAR_SIZE, "big")

        # 2) Шифрование
        nonce = secrets.token_bytes(16)  # AES-CTR nonce/counter block
        ciphertext = self._aes256_ctr_crypt(aes_key, nonce, data)

        # 3) Хэш шифротекста
        digest = hashlib.sha256(ciphertext).digest()

        # 4) Reed-Solomon по ciphertext
        cipher_shards, rs_meta = self._rs_encode_systematic(ciphertext, k, n)

        # 5) Pedersen-Shamir по ключу
        ps = PedersenShamirEC(self.curve_def, t=k, n=n)
        shares, commitments, _, _ = ps.share(secret_int)

        # 6) Пакеты P_i
        packets: List[bytes] = []
        for shard_payload, share in zip(cipher_shards, shares):
            x, y, z = share
            masked_y = self._xor_bytes(y.to_bytes(self.SCALAR_SIZE, "big"), digest)
            packet = self._pack_packet(
                x=x,
                masked_y=masked_y,
                z=z.to_bytes(self.SCALAR_SIZE, "big"),
                shard=shard_payload,
            )
            packets.append(packet)

        meta = {
            "scheme": "aes256-rs-pedersen-shamir",
            "cipher": "AES-256-CTR",
            "hash": "SHA-256",
            "curve": self.curve_def.name,
            "threshold": k,
            "total_shares": n,
            "nonce_hex": nonce.hex(),
            "ciphertext_len": len(ciphertext),
            "rs_padding": rs_meta["padding"],
            "ps_h": self._point_to_json(ps.H),
            "ps_commitments": [self._point_to_json(p) for p in commitments],
            "packet_format": {
                "x": "uint32",
                "masked_y": "32 bytes",
                "z": "32 bytes",
                "shard_length": "uint32",
                "shard": "bytes",
            },
        }
        return packets, meta

    def recover_and_decrypt(
        self,
        shards_data: List[Tuple[int, bytes]],
        k: int,
        n: int,
        meta: Dict,
    ) -> bytes:
        """
        Восстановление с перебором сочетаний пакетов.
    
        """
        if len(shards_data) < k:
            raise ValueError(f"Need at least {k} packets, got {len(shards_data)}")

        # 1) Парсим все пришедшие пакеты
        parsed_packets = []
        seen_indexes = set()

        for shard_index, raw_packet in shards_data:
            if shard_index in seen_indexes:
                continue
            seen_indexes.add(shard_index)

            try:
                x, masked_y, z, shard_payload = self._unpack_packet(raw_packet)
                parsed_packets.append({
                    "shard_index": shard_index,
                    "x": x,
                    "masked_y": masked_y,
                    "z": z,
                    "cipher_shard": shard_payload,
                })
            except Exception:
                # Полностью битый пакет даже не участвует в переборе
                continue

        if len(parsed_packets) < k:
            raise ValueError(
                f"Not enough parsable packets after packet parsing: got {len(parsed_packets)}, need {k}"
            )

        # 2) Восстанавливаем публичные параметры Pedersen-Shamir
        H = self._point_from_json(meta["ps_h"])
        commitments = [self._point_from_json(p) for p in meta["ps_commitments"]]
        ps = PedersenShamirEC(self.curve_def, t=k, n=n, H=H)

        last_error: Exception | None = None

        # 3) Перебираем сочетания.

        for subset in combinations(parsed_packets, k):
            try:
                cipher_shards = [
                    (packet["shard_index"], packet["cipher_shard"])
                    for packet in subset
                ]

                ciphertext = self._rs_decode_systematic(
                    shards_data=cipher_shards,
                    k=k,
                    n=n,
                    ciphertext_len=meta["ciphertext_len"],
                )

                # Считаем хэш от восстановленного шифротекста
                digest = hashlib.sha256(ciphertext).digest()

                # Снимаем маску с долей и проверяем их по commitments
                valid_shares: List[Tuple[int, int, int]] = []
                invalid_indexes: List[int] = []

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

                # 4 Восстанавливаем AES-ключ
                secret_int = ps.reconstruct(valid_shares[:k])
                aes_key = secret_int.to_bytes(self.SCALAR_SIZE, "big")

                # 5 Расшифровываем
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


    # ---------- AES ----------

    def _aes256_ctr_crypt(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        transform = cipher.encryptor()
        return transform.update(data) + transform.finalize()

    # ---------- RS ----------

    def _rs_encode_systematic(self, data: bytes, k: int, n: int) -> Tuple[List[bytes], Dict]:

        if not data:
            raise ValueError("Empty input is not allowed")
        if not (2 <= k <= n <= 255):
            raise ValueError("Require 2 <= k <= n <= 255 for GF(256)")

        original_len = len(data)
        shard_len = math.ceil(original_len / k)
        padded_len = shard_len * k
        padding_len = padded_len - original_len
        padded_data = data + (b"\x00" * padding_len)

        data_shards = [
            padded_data[i * shard_len:(i + 1) * shard_len]
            for i in range(k)
        ]

        if n == k:
            shards = data_shards
        else:
            G = self._build_systematic_generator_matrix(k, n)
            parity_matrix = G[k:]
            parity_shards = self._apply_matrix_to_shards(parity_matrix, data_shards)
            shards = data_shards + parity_shards

        return shards, {
            "orig_len": original_len,
            "padding": padding_len,
            "shard_len": shard_len,
            "coding": "systematic-gf256-matrix",
        }

    def _rs_decode_systematic(
        self,
        shards_data: List[Tuple[int, bytes]],
        k: int,
        n: int,
        ciphertext_len: int,
    ) -> bytes:
        """
        Восстановление из любых k shard'ов через обращение подматрицы G.
        """
        if not (2 <= k <= n <= 255):
            raise ValueError("Require 2 <= k <= n <= 255 for GF(256)")
        if len(shards_data) < k:
            raise ValueError(f"Need at least {k} shards")

        shard_map: Dict[int, bytes] = {}
        for idx, shard in shards_data:
            if not (0 <= idx < n):
                raise ValueError(f"Shard index out of range: {idx}")
            if idx not in shard_map:
                shard_map[idx] = shard

        if len(shard_map) < k:
            raise ValueError(f"Need at least {k} unique shards")

        available = sorted(shard_map.items(), key=lambda x: x[0])[:k]
        selected_indexes = [idx for idx, _ in available]
        selected_shards = [shard for _, shard in available]

        shard_len = len(selected_shards[0])
        if any(len(s) != shard_len for s in selected_shards):
            raise ValueError("All provided shards must have the same length")

        if n == k:
            if selected_indexes != list(range(k)):
                raise ValueError("For n == k, all original data shards 0..k-1 are required")
            recovered_data_shards = selected_shards
        else:
            G = self._build_systematic_generator_matrix(k, n)
            A = [G[idx][:] for idx in selected_indexes]
            A_inv = self._gf256_matrix_invert(A)
            recovered_data_shards = self._apply_matrix_to_shards(A_inv, selected_shards)

        recovered = b"".join(recovered_data_shards)
        return recovered[:ciphertext_len]

    # Some utils

    def _pack_packet(self, *, x: int, masked_y: bytes, z: bytes, shard: bytes) -> bytes:
        if len(masked_y) != self.SCALAR_SIZE:
            raise ValueError("masked_y must be 32 bytes")
        if len(z) != self.SCALAR_SIZE:
            raise ValueError("z must be 32 bytes")

        header = struct.pack(self.PACKET_HEADER_FORMAT, x, len(shard))
        return header + masked_y + z + shard

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


    @staticmethod
    def _xor_bytes(left: bytes, right: bytes) -> bytes:
        if len(left) != len(right):
            raise ValueError("XOR operands must have the same length")
        return bytes(a ^ b for a, b in zip(left, right))