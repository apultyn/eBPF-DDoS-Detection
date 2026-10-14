from urllib.request import urlopen
import pandas as pd
from datetime import datetime

url = "http://127.0.0.1:18000/CSV-03-11/03-11/portmap.csv"
total_rows = 0

with urlopen(url, timeout=60) as response:
    with pd.read_csv(
        response,
        encoding="utf-8-sig",
        chunksize=50_000,
    ) as reader:
        start = time.now()
        for i, chunk in enumerate(reader):
            print(f"Reading {i+1} chunk...")
            # Filter, aggregate, or extract features here.
            total_rows += len(chunk)
        print(f"Time: {time.now() - start}")

print(f"Processed {total_rows:,} rows")
