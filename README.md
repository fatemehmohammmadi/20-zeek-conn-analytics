# 20 — Zeek conn.log Analytics

Analyze Zeek-style **conn.log** records: top talkers, rare services, long connections, and simple anomaly flags for hunting demos.

## Run

```bash
pip install -r requirements.txt
python generate_connlog.py
python analyze_connlog.py
```

## Sample outputs

- `outputs/summary.json`
- `outputs/top_talkers.csv`
- `outputs/rare_services.csv`
- `outputs/anomalous_conns.csv`
