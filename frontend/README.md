# MyRecon Frontend

Frontend console adapted to the existing recon workflow and PostgreSQL-backed data model.

## Scope Alignment

This UI maps to the current backend flow:

1. Subdomain discovery (`subs`)
2. Optional active expansion (`active-subs`)
3. Service discovery (`ports`, `witness`)
4. Vulnerability candidate collection (`nuclei`)
5. Monitor changes (`monitor_targets`, `monitor_runs`, `asset_changes`, `port_changes`)

## Expected API Endpoints

- `GET /api/dashboard/summary`
- `GET /api/jobs`
- `POST /api/jobs`
- `GET /api/assets`
- `GET /api/ports`
- `GET /api/vulns`
- `GET /api/monitor/targets`
- `GET /api/monitor/runs`
- `GET /api/monitor/changes`

## Run (local)

```bash
npm ci
npm run dev
```

Set API target if your backend is not on `127.0.0.1:8090`:

```bash
VITE_API_TARGET=http://127.0.0.1:8090 npm run dev
```

## Run (docker)

```bash
docker build -t myrecon-frontend .
docker run --rm -p 8080:80 --add-host=host.docker.internal:host-gateway myrecon-frontend
```
