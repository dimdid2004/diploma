import csv
import hashlib
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt

from split_algorithms import AlgorithmsManager


def generate_deterministic_bytes(size: int) -> bytes:
    """
    Детерминированная генерация данных заданного размера.
    Нужна для воспроизводимых тестов.
    """
    result = bytearray()
    counter = 0
    while len(result) < size:
        seed = f"bench-{size}-{counter}".encode("utf-8")
        result.extend(hashlib.sha256(seed).digest())
        counter += 1
    return bytes(result[:size])


def human_size(num_bytes: int) -> str:
    mb = 1024 * 1024
    if num_bytes >= mb:
        return f"{num_bytes / mb:.2f} MB"
    return f"{num_bytes / 1024:.2f} KB"


def default_sizes() -> list[int]:
    mb = 1024 * 1024
    return [
        1 * mb,
        2 * mb,
        5 * mb,
        10 * mb,
        20 * mb,
        50 * mb,
        75 * mb,
        100 * mb,
    ]


def benchmark_once(size: int, k: int, n: int) -> dict:
    manager = AlgorithmsManager()
    data = generate_deterministic_bytes(size)

    split_start = time.perf_counter()
    shards, meta = manager.encrypt_and_disperse(data, k, n)
    split_elapsed = time.perf_counter() - split_start

    shards_data = [(idx, shard) for idx, shard in enumerate(shards[:k])]

    restore_start = time.perf_counter()
    restored = manager.recover_and_decrypt(shards_data, k, n, meta)
    restore_elapsed = time.perf_counter() - restore_start

    if restored != data:
        raise ValueError("Restored data does not match original")

    return {
        "split_seconds": split_elapsed,
        "restore_seconds": restore_elapsed,
    }


def benchmark_sizes(
    sizes: list[int],
    k: int = 4,
    n: int = 6,
    repeats: int = 3,
    warmups: int = 1,
) -> list[dict]:
    rows = []

    for size in sizes:
        print(f"\nРазмер: {human_size(size)}")

        for warmup_idx in range(warmups):
            _ = benchmark_once(size, k, n)
            print(f"  warmup {warmup_idx + 1}/{warmups} done")

        split_times = []
        restore_times = []

        for repeat_idx in range(repeats):
            result = benchmark_once(size, k, n)
            split_times.append(result["split_seconds"])
            restore_times.append(result["restore_seconds"])

            print(
                f"  repeat {repeat_idx + 1}/{repeats}: "
                f"split={result['split_seconds']:.4f}s, "
                f"restore={result['restore_seconds']:.4f}s"
            )

        row = {
            "size_bytes": size,
            "size_mb": size / (1024 * 1024),
            "split_mean": statistics.mean(split_times),
            "split_stdev": statistics.stdev(split_times) if len(split_times) > 1 else 0.0,
            "restore_mean": statistics.mean(restore_times),
            "restore_stdev": statistics.stdev(restore_times) if len(restore_times) > 1 else 0.0,
        }
        rows.append(row)

        print(
            f"  mean split:   {row['split_mean']:.4f}s | "
            f"mean restore: {row['restore_mean']:.4f}s"
        )

    return rows


def save_csv(rows: list[dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "size_bytes",
                "size_mb",
                "split_mean",
                "split_stdev",
                "restore_mean",
                "restore_stdev",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def plot_graph(
    rows: list[dict],
    metric_key: str,
    ylabel: str,
    title: str,
    output_path: Path,
) -> None:
    xs = [row["size_mb"] for row in rows]
    ys = [row[metric_key] for row in rows]

    plt.figure(figsize=(10, 6))
    plt.plot(xs, ys, marker="o")
    plt.xlabel("Размер входного файла, MB")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path, dpi=160)
    plt.close()


def main():
    output_dir = Path("benchmark_results")
    output_dir.mkdir(exist_ok=True)

    sizes = default_sizes()
    k = 4
    n = 6
    repeats = 3
    warmups = 1

    print("Параметры:")
    print(f"  k={k}, n={n}")
    print(f"  repeats={repeats}, warmups={warmups}")
    print(f"  sizes={[human_size(s) for s in sizes]}")
    print(f"  output_dir={output_dir.resolve()}")

    rows = benchmark_sizes(
        sizes=sizes,
        k=k,
        n=n,
        repeats=repeats,
        warmups=warmups,
    )

    csv_path = output_dir / "benchmark_results.csv"
    split_plot_path = output_dir / "split_time_vs_size.png"
    restore_plot_path = output_dir / "restore_time_vs_size.png"

    save_csv(rows, csv_path)

    plot_graph(
        rows,
        metric_key="split_mean",
        ylabel="Время разделения, s",
        title="Время разделения в зависимости от размера входных данных",
        output_path=split_plot_path,
    )

    plot_graph(
        rows,
        metric_key="restore_mean",
        ylabel="Время восстановления, s",
        title="Время восстановления в зависимости от размера входных данных",
        output_path=restore_plot_path,
    )

    print("\nГотово.")
    print(f"CSV:      {csv_path}")
    print(f"Split:    {split_plot_path}")
    print(f"Restore:  {restore_plot_path}")


if __name__ == "__main__":
    main()