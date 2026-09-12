import os
import time
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


BASE_DIR = (
    '/content/drive/MyDrive/ML-DDoS'
    if os.path.exists('/content/drive/MyDrive/ML-DDoS')
    else os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'
        )
        if '__file__' in globals()
        else '.'
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    'data',
    'divided'
)


def serialize(csv_path, parquet_path, chunksize=1000000):
    name = os.path.basename(csv_path)
    pq_name = os.path.basename(parquet_path)

    print("\n" + "=" * 60)
    print(f"[*] Serializing: {name} -> {pq_name}")
    print("=" * 60)

    if not os.path.exists(csv_path):
        print(f"[-] Error: File not found: {csv_path}")
        return

    t = time.time()
    sample = pd.read_csv(
        csv_path,
        nrows=1
    )

    fields = [
        pa.field(col, pa.float32())
        for col in sample.columns
        if col != 'Label'
    ]
    fields.append(pa.field('Label', pa.int16()))
    schema = pa.schema(fields)

    writer = None
    total_flows = 0

    chunks = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False
    )

    for chunk in chunks:
        chunk = chunk.dropna(subset=['Label'])
        if chunk.empty:
            continue

        for col in chunk.columns:
            if col == 'Label':
                chunk[col] = pd.to_numeric(chunk[col], errors='coerce').fillna(0).astype(np.int16)
            else:
                chunk[col] = pd.to_numeric(chunk[col], errors='coerce').fillna(0.0).astype(np.float32)

        table = pa.Table.from_pandas(
            chunk,
            schema=schema,
            preserve_index=False
        )
        if writer is None:
            writer = pq.ParquetWriter(
                parquet_path,
                schema,
                compression='snappy'
            )
        writer.write_table(table)
        total_flows += len(chunk)
        print(f"[*] Processed {total_flows:,} flows...", end='\r')

    if writer is not None:
        writer.close()

    raw_mb = os.path.getsize(csv_path) / (1024 * 1024)
    pq_mb = os.path.getsize(parquet_path) / (1024 * 1024)
    saved = (1.0 - (pq_mb / raw_mb)) * 100.0

    print(f"\n[+] Saved parquet: {parquet_path}")
    print(f"[+] Total flows:   {total_flows:,}")
    print(f"[+] Compression:   {raw_mb:.1f} MB -> {pq_mb:.1f} MB (Saved {saved:.1f}%)")
    print(f"[+] Completed in {time.time() - t:.2f}s")


def main():
    total_start = time.time()

    train_csv = os.path.join(
        DATA_DIR,
        'train.csv'
    )
    train_pq = os.path.join(
        DATA_DIR,
        'train.parquet'
    )

    test_csv = os.path.join(
        DATA_DIR,
        'test.csv'
    )
    test_pq = os.path.join(
        DATA_DIR,
        'test.parquet'
    )

    serialize(
        train_csv,
        train_pq
    )

    serialize(
        test_csv,
        test_pq
    )

    print("\n" + "=" * 60)
    print("[+] FINISHED!")
    print(f"[+] Total time: {time.time() - total_start:.2f}s")
    print("=" * 60)


if __name__ == '__main__':
    main()
