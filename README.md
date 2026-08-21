# WrongDoor

Dynamic authorization tester for HTTP APIs. It logs in as several identities, has each one create its own data, then tries to reach that data as somebody else. When it finds a leak it hands you the exact pair of requests that proves it.

Most authorization scanners guess. They fire an id at an endpoint and judge the result by the status code. WrongDoor doesn't guess. It creates the data itself, which means it knows who owns every object. That lets it confirm a leak by matching the response against the owner's own copy.

## What it finds

| Check | Question it asks | How it confirms |
|---|---|---|
| BOLA / IDOR | Can one user read another user's object? | The response body contains the owner's object |
| Missing auth | Can an anonymous caller read it? | Same body match, with no credentials at all |
| BFLA | Can a normal user call an admin-only operation? | The privileged call returns 2xx |
| Mass assignment | Can a user set a field they shouldn't control? | The field is re-read and it actually changed |

Every finding is reported with a severity, a plain-English explanation, a suggested fix, and a reproducible request pair.

## Requirements

Python 3.12 or newer.

## Quickstart

This runs the tool end to end against the bundled vulnerable demo API. It should take about a minute. The demo is deliberately insecure and only listens on 127.0.0.1.

### 1. Install

```bash
git clone https://github.com/aroh3006/WrongDoor.git
cd WrongDoor
python -m venv .venv
```

Activate the virtual environment.

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

bash/zsh:

```bash
source .venv/bin/activate
```

Then install the tool with its dev extras (the demo API needs them):

```bash
pip install -e ".[dev]"
```

### 2. Start the demo API

Leave this running in its own terminal:

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --app-dir examples/vulnerable-api
```

### 3. Set the demo passwords

The config never stores secrets. It only names the environment variables that hold them. Set these in the **same terminal** you are going to run `wrongdoor` from, not the one running the API.

PowerShell:

```powershell
$env:ALICE_PW = "alice-pw"
$env:BOB_PW = "bob-pw"
```

bash/zsh:

```bash
export ALICE_PW="alice-pw"
export BOB_PW="bob-pw"
```

These two values are the demo's hardcoded passwords. A real target would use real ones.

### 4. Check the setup before sending anything

`lint` runs offline. It sends no requests. It also warns you if a password variable is missing, which is the most common setup mistake:

```bash
wrongdoor lint -c examples/vulnerable-api/config.yaml -s examples/vulnerable-api/openapi.yaml
```

Then confirm both identities can actually log in:

```bash
wrongdoor auth-check -c examples/vulnerable-api/config.yaml --confirm-own-target
```

You should see a `200` for both alice and bob.

### 5. Run it

```bash
wrongdoor run -c examples/vulnerable-api/config.yaml -s examples/vulnerable-api/openapi.yaml --confirm-own-target
```

You should get 10 findings and exit code 1:

```
checks: 24   violations=10   pass=14   broken=0   inconclusive=0

by severity: CRITICAL=2   HIGH=8
by type:     BFLA=2   BOLA=6   MISSING_AUTH=2
```

Each finding prints like this:

```
+----------------------- CRITICAL | BOLA | getInvoice ------------------------+
| severity:  CRITICAL                                                         |
| actor:     bob (tenant B)                                                   |
| victim:    alice (tenant A) owns invoices/1024                              |
| operation: GET getInvoice                                                   |
|                                                                             |
| reproducible request pair:                                                  |
|   canonical: GET /invoices/1024 (as alice) -> 200                           |
|   attack:    GET /invoices/1024 (as bob) -> 200                             |
|                                                                             |
| body match: amount, id, memo, owner, tenant                                 |
|                                                                             |
| fix: Enforce an ownership/tenancy check on GET getInvoice before returning  |
| the object: verify the invoices belongs to the caller (e.g. WHERE id = :id  |
| AND owner = current_user) and return 403/404 otherwise.                     |
+-----------------------------------------------------------------------------+
```

### 6. Try the extras

Clean up the objects the run created:

```bash
wrongdoor run -c examples/vulnerable-api/config.yaml -s examples/vulnerable-api/openapi.yaml --confirm-own-target --cleanup
```

Include write-based checks, which adds the mass-assignment detector (12 findings instead of 10):

```bash
wrongdoor run -c examples/vulnerable-api/config.yaml -s examples/vulnerable-api/openapi.yaml --confirm-own-target --include-mutations
```

Write an HTML report:

```bash
wrongdoor run -c examples/vulnerable-api/config.yaml -s examples/vulnerable-api/openapi.yaml --confirm-own-target --format html -o report.html
```

Run against a recorded HAR capture instead of an OpenAPI spec:

```bash
wrongdoor run -c examples/vulnerable-api/config.yaml -s examples/har/demo.har --confirm-own-target
```

## Safety

This tool authenticates as real users and creates real data. Two gates stand in front of every request.

1. Every target host must be listed in `target.allow` in your config. The match is exact. Anything else is refused.
2. You have to pass `--confirm-own-target` to confirm you own the target or are authorized to test it.

Writes are off by default. `--include-mutations` turns them on. Seeding is capped by `seeding.max_objects` so a bad config can't create a runaway amount of data. Use `--dry-run` to see what a run would do without sending anything.

Secrets are only ever referenced by environment variable name. They are never written to the config file and never printed. Reports show the *names* of matched fields, not their values, unless you explicitly pass `--include-bodies`.

## Configuration

A minimal config looks like this:

```yaml
target:
  base_url: http://127.0.0.1:8000
  allow: [127.0.0.1]          # the guard refuses any host not listed here
identities:
  - id: alice
    attributes: {tenant: A}
    auth: {type: login, url: /login, username: alice, password_env: ALICE_PW}
  - id: bob
    attributes: {tenant: B}
    auth: {type: bearer, token_env: BOB_TOKEN}
resources:
  invoices: {sensitivity: high}   # drives severity scoring
```

Supported auth types are `login`, `bearer`, `api_key`, and `oauth2`. See `examples/vulnerable-api/config.yaml` for a fuller example with dependencies, privileged operations, and mass-assignment fields.

## Commands

| Command | What it does |
|---|---|
| `wrongdoor lint` | Offline check of the config and spec. Sends no requests. |
| `wrongdoor auth-check` | Log in as every identity and hit a probe endpoint. |
| `wrongdoor seed` | Create one object per identity and print the ownership ledger. |
| `wrongdoor run` | The full pipeline: seed, sweep, judge, report. |

Useful `run` flags: `--dry-run`, `--include-mutations`, `--cleanup`, `--format`, `-o/--output`, `--fail-on`, `--include-bodies`.

## Report formats

`--format` accepts `terminal` (default), `json`, `sarif`, `junit`, and `html`. Everything except `terminal` writes clean machine-readable output to stdout. That means it pipes:

```bash
wrongdoor run -c config.yaml -s openapi.yaml --confirm-own-target --format json | jq '.summary'
```

SARIF uploads to GitHub code scanning. JUnit plugs into most CI dashboards.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Ran fine, nothing at or above the `--fail-on` threshold |
| 1 | A finding at or above `--fail-on` (default `low`) |
| 2 | Config error |
| 3 | Refused by the safety guard |
| 4 | Authentication failed |
| 5 | The spec could not be parsed |

## CI

A GitHub Action is included in `action/`. See `.github/workflows/ci.yml` for a working example that starts the demo API, runs the tool against it, and fails the build on a confirmed leak.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## How it works

1. **Load and lint.** The config and spec are validated offline first.
2. **Authenticate.** Each identity gets its own session.
3. **Seed.** Every identity creates its own objects. Ownership gets recorded in a ledger. This is the ground truth everything else depends on.
4. **Plan.** Build the matrix of cross-identity requests worth trying.
5. **Execute.** Replay the matrix concurrently, with a cap on in-flight requests.
6. **Judge.** A pure function decides each result: PASS, VIOLATION, BROKEN, or INCONCLUSIVE. A `2xx` on its own is never a leak. The body has to match the owner's object.
7. **Report.** Score, explain, and print.

`DECISIONS.md` explains why each of these works the way it does.

## License

Apache-2.0. See `LICENSE`.
