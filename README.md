# Zeek conn.log Analytics

Hunting helpers over a Zeek-style `conn.log` CSV: top talkers, rare services, and simple p99 anomalies on duration / bytes.

## Run

```bash
pip install -r requirements.txt
python generate_connlog.py
python analyze_connlog.py
```

## Outputs

| File | Contents |
|------|----------|
| `outputs/summary.json` | high-level counts + thresholds |
| `outputs/top_talkers.csv` | chatty origins |
| `outputs/rare_services.csv` | low-share services |
| `outputs/anomalous_conns.csv` | long or heavy rows |

## Notes

Column names follow Zeek (`id.orig_h`, `id.resp_p`, …) so it's easier to point at a real export later. The generator plants a few obvious outliers up front.

## License

MIT
