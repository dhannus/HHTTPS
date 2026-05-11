# Flask + HHTTPS — Online petition example

An online petition that accepts signatures only from HHTTPS-verified humans.

## Run
```bash
pip install -r requirements.txt
python app.py
```

## Endpoints
| Path | Auth |
|---|---|
| GET  /                     | public |
| POST /sign                 | trust ≥ 60 |
| POST /sign/professional    | role in {lawyer, researcher, doctor, civil_servant}, trust ≥ 85 |
| GET  /signatures           | public (anonymized) |
