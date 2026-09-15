"""Generate Zeek-like conn.log CSV rows."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

RNG = np.random.default_rng(2020)
OUT = Path(__file__).parent / "data" / "conn.log.csv"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    n = 1200
    services = RNG.choice(["http", "ssl", "dns", "ssh", "smb", "-"], size=n, p=[0.25, 0.3, 0.2, 0.1, 0.05, 0.1])
    df = pd.DataFrame(
        {
            "ts": pd.date_range("2026-02-01", periods=n, freq="min"),
            "id.orig_h": [f"10.0.{RNG.integers(0,3)}.{RNG.integers(1,80)}" for _ in range(n)],
            "id.resp_h": [f"198.51.100.{RNG.integers(1,50)}" for _ in range(n)],
            "id.resp_p": RNG.choice([80, 443, 53, 22, 445, 8080, 3389], size=n),
            "proto": RNG.choice(["tcp", "udp", "icmp"], size=n, p=[0.8, 0.18, 0.02]),
            "service": services,
            "duration": RNG.exponential(2.0, n).round(3),
            "orig_bytes": RNG.lognormal(7.5, 1.0, n).astype(int),
            "resp_bytes": RNG.lognormal(7.0, 1.1, n).astype(int),
            "conn_state": RNG.choice(["SF", "S0", "REJ", "RSTO"], size=n, p=[0.7, 0.15, 0.1, 0.05]),
        }
    )
    # plant a few long + heavy outliers
    for i in range(15):
        df.loc[i, "duration"] = float(RNG.uniform(500, 2000))
        df.loc[i, "orig_bytes"] = int(RNG.integers(5_000_000, 20_000_000))
        df.loc[i, "service"] = "-"
    df.to_csv(OUT, index=False)
    print(f"Wrote {len(df)} conn rows -> {OUT}")


if __name__ == "__main__":
    main()
