# output/

Everything the analysis produces:

| File | Content |
|---|---|
| `hayabusa-output.csv` | the correlated timeline |
| `<case>-console.log` | the full session log, including what the interface only sampled |
| `thor-lite.log` | raw THOR output, parsed into the YARA view |
| `cylr.log` | collection log |
| `enrichment-cache.json` | VirusTotal / AbuseIPDB answers, so a quota is only paid once |

The printable report and the JSON export are served from the console rather than
written here: **Report** and **JSON** in the top-right of the dashboard.
