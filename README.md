# PurpleLab

PurpleLab is a fixture-driven detection engineering validation platform. It evaluates local Sigma-style rules against harmless, generated event data, persists run evidence, and reports detection, telemetry, false-positive, latency, and ATT&CK coverage metrics.

## Safety

Fixture collection remains the default. The runner serializes test event dictionaries to local JSONL files; it never launches processes, writes registry keys, or generates network traffic. The safety gate enforces event limits, approval policy, timeouts, and fixture-only targets. Optional Phase 2 collectors only read: Elastic, Splunk, Sentinel, Sysmon EVTX exports, Zeek logs, and Suricata EVE logs. They require explicit endpoint/path configuration and correlate results by PurpleLab run ID.

## Quickstart

Requirements: Docker Compose. Start the complete stack:

```powershell
docker compose up --build
```

Open the dashboard at `http://localhost:5173`, API docs at `http://localhost:8000/docs`, or health at `http://localhost:8000/health`.

## Local Development

Requirements: Python 3.11+, Node.js 20+, and PostgreSQL 16. Start the database with `docker compose up -d db`, create `.env` from `.env.example`, configure only the integrations you intend to query, then:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn app.main:app --app-dir backend --reload
```

In a second terminal:

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
```

Run backend tests with `python -m pytest`. The async runner integration uses in-memory SQLite; the application uses PostgreSQL by default.

Install `python-evtx` through the project dependencies to read configured EVTX exports. Sensor log paths and remote collector credentials are optional; leave them unset to keep the fixture collector active.

## Operator CLI

After `python -m pip install -e .`, use:

```powershell
purplelab scenarios
purplelab run process_event_unusual_parent
purplelab run-all
purplelab coverage
purplelab techniques
purplelab collectors
purplelab snapshot
```

## API

- `GET /health` and `GET /ready`
- `GET /api/scenarios`, `GET /api/scenarios/{scenario_id}`, `POST /api/scenarios/sync`
- `GET /api/rules`, `POST /api/rules/validate`
- `POST /api/normalize`, `GET /api/collectors`, `GET /api/collectors/health`
- `GET /api/executions`, `GET /api/executions/{execution_id}`
- `POST /api/executions/run/{scenario_key}`, `POST /api/executions/run-all`
- `GET /api/coverage`, `/api/coverage/attck`, `/api/coverage/history`, `POST /api/coverage/snapshot`

Scenario definitions live in `scenarios/`, Sigma-style rules in `rules/sigma/`, and execution event/alert JSONL files in `fixtures/`. PostgreSQL schema is defined in `migrations/001_initial.sql`; tables and local catalogs are also initialized on application startup.

## Phase 2 Integrations

`POST /api/normalize` maps Sysmon, ECS-like, Zeek, Suricata, and generic JSON events to a canonical event shape while retaining raw fields and a flat Sigma lookup map. Sigma matching supports `contains`, `startswith`, `endswith`, `re`, `cidr`, `base64`, `base64offset`, `windash`, `all`, boolean conditions, and selection quantifiers. Nested rules under `rules/sigma/advanced/` are loaded at startup; `rules/sigma/mappings/field_mappings.yaml` documents common vendor aliases.

The collector is selected with `PURPLELAB_DEFAULT_COLLECTOR` and defaults to `fixture`. Configure Elastic, Splunk, Sentinel, Sysmon EVTX, Zeek, or Suricata settings in `.env`; remote endpoints require HTTPS and correlation run IDs are strictly validated. The EVTX reader uses `python-evtx` and reads configured export files only. Collectors do not issue writes or execute queries supplied by users.

## Outcomes and Metrics

Execution outcomes remain distinct: `detected`, `detection_failed`, `telemetry_unavailable`, `blocked`, `negative_pass`, `negative_fail`, and `error`. Coverage excludes untested scenarios from detection failures. The weighted Detection Reliability Score is a proposed metric and must be validated against labeled data before being treated as authoritative.
