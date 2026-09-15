"""Hunt-style analytics over Zeek conn.log CSV."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

DATA = Path(__file__).parent / "data" / "conn.log.csv"
OUT = Path(__file__).parent / "outputs"


def main() -> None:
    if not DATA.exists():
        raise SystemExit("Run generate_connlog.py first.")
    OUT.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATA)

    talkers = (
        df.groupby("id.orig_h")
        .agg(conns=("id.resp_h", "size"), bytes_out=("orig_bytes", "sum"), unique_dst=("id.resp_h", "nunique"))
        .sort_values("bytes_out", ascending=False)
        .head(20)
        .reset_index()
    )
    talkers.to_csv(OUT / "top_talkers.csv", index=False)

    svc = df["service"].value_counts(normalize=True)
    rare = svc[svc < 0.08].rename("share").reset_index().rename(columns={"index": "service"})
    if "service" not in rare.columns:
        rare.columns = ["service", "share"]
    rare.to_csv(OUT / "rare_services.csv", index=False)

    dur_p99 = df["duration"].quantile(0.99)
    bytes_p99 = df["orig_bytes"].quantile(0.99)
    anom = df[(df["duration"] >= dur_p99) | (df["orig_bytes"] >= bytes_p99)].copy()
    anom["reason"] = anom.apply(
        lambda r: ";".join(
            x
            for x, cond in (
                ("long_duration", r["duration"] >= dur_p99),
                ("heavy_orig_bytes", r["orig_bytes"] >= bytes_p99),
            )
            if cond
        ),
        axis=1,
    )
    anom.sort_values("orig_bytes", ascending=False).head(40).to_csv(OUT / "anomalous_conns.csv", index=False)

    summary = {
        "n_conns": int(len(df)),
        "unique_orig": int(df["id.orig_h"].nunique()),
        "unique_resp": int(df["id.resp_h"].nunique()),
        "duration_p99": round(float(dur_p99), 3),
        "orig_bytes_p99": int(bytes_p99),
        "anomalous_count": int(len(anom)),
        "top_services": df["service"].value_counts().head(5).to_dict(),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
