# WrongDoor — Complete Technical Blueprint (Dynamic Live-Testing Design)

> A dynamic authorization tester: it runs against a **live API**, creates real data as each identity, then proves whether one identity can reach another's data — producing a **reproducible HTTP request pair** as evidence.
> Design principle throughout: **simple engineering + serious cybersecurity.**
> Test at every step: *could a motivated final-year cyber student build this alone and explain every line?* If not, simplify.

---

## What this design is (and why we reverted to it)

An earlier draft pivoted to a *static* analyzer that ingests a hand-written YAML authorization model and checks it for internal consistency. That was the wrong call, for three reasons you correctly identified:

1. **The static version can only tell you your *model* is self-consistent — not that your *app* is safe.** If the YAML doesn't match reality, it proves nothing. And model-vs-reality drift is exactly the failure mode that produces authorization bugs in the first place.
2. **It stopped representing your actual experience.** You did *manual, live* authorization testing against a real API at AdlerQA. The dynamic tool automates that; the static one doesn't.
3. **The BloodHound analogy backfired.** BloodHound's power is that it collects the *real* permission graph from a running system, not a description of intentions. A YAML-only model has no collector, so it can't see drift.

So WrongDoor is a **dynamic differential authorization tester**. Its core is:
- a **YAML identity/ownership DSL** (who exists, how they authenticate, who *should* be able to touch what),
- a **seeding engine** that creates real objects as each identity against the live target and records **true ownership by construction**,
- an **async matrix executor** that replays operations across every non-owner identity, and
- a **verdict engine** that compares expected vs. observed responses and confirms leaks by matching response bodies against the known owner's data.

Reporting (SARIF/JUnit/HTML) and a GitHub Action are kept. A small **static "sanity check" pre-flight** (typos, dangling references, dependency cycles in the YAML) survives as an optional bonus that runs *before* the live test — it catches config mistakes cheaply, but it is not the product.

**The honest tradeoff, stated up front:** the dynamic design needs a *running target* and it *creates (and sometimes mutates) real data*. That is the price of testing reality instead of intentions, and §13 is dedicated to making that safe. Determinism and testability — the things the static version was good at — are recovered here through (a) the ownership ledger, which gives ground-truth verdicts instead of heuristics, and (b) a deliberately-vulnerable demo API with known planted bugs, which is your known-answer test harness (§16).

---

# 1. What exactly is WrongDoor?

**One-sentence definition:**
WrongDoor is a tool that logs into a live API as several different users, has each user create their own data, then automatically checks whether any user can read, change, or delete another user's data — and if so, hands you the exact two requests that prove it.

**Short product description:**
You describe your API's users and how they authenticate in a small YAML file, and point WrongDoor at a running (test) instance of your API plus its OpenAPI spec. WrongDoor authenticates as each user, creates real resources as each of them (recording exactly who owns what), then replays every operation as every *other* user. When a non-owner successfully accesses an owner's object, WrongDoor confirms the leak by matching the response body against the owner's known data and reports it with a reproducible `curl` pair, a severity, and a fix. It emits SARIF/JUnit so it can fail a CI build the moment an authorization check regresses.

**Technical definition:**
WrongDoor is a black-box, differential, dynamic authorization testing engine. From a declarative identity/ownership specification and an OpenAPI description of the target, it (1) establishes an authenticated session per identity, (2) executes resource-creating operations per identity and records `object_id → owning_identity` in an **ownership ledger** (ground truth by construction), (3) plans an `operation × identity × object` test matrix excluding self-owned combinations, (4) executes the matrix asynchronously against the live target, and (5) evaluates each result with a verdict engine that compares the observed response to the policy-expected outcome and confirms data exposure via owner-response body matching. Findings carry the exact request/response evidence, a deterministic severity, and remediation, and are emitted to terminal, JSON, SARIF, JUnit, and HTML.

**The central security concept:** *Authorization is a claim about the real running system, and the only way to know if it holds is to try it.* A scanner can't detect broken object-level authorization by looking at a response in isolation, because a leaked object returns a perfectly valid `200 OK`. WrongDoor makes the leak *decidable* by knowing — because it created the object — who the object truly belongs to. Ground-truth ownership turns a guess into a proof.

**Simplest possible version (the true MVP):**
A CLI that (a) authenticates two identities from a YAML file, (b) has each `POST` one resource and records the returned ID and owner, (c) has each identity `GET` the *other's* resource, and (d) reports a finding when a non-owner gets `200` with a body matching the owner's object. That seed — two users, one create, one cross-read, one body-match verdict — is the whole tool in miniature. Everything else scales it up.

**Is this realistic and worthwhile for a final-year project?**
Yes, and it's the strongest option on the table for you specifically. Worthwhile: broken object-level authorization is the #1 API security risk and the class automated scanners structurally miss, so a tool that *confirms* it is genuinely useful, not academic. Realistic: the MVP has **no database, no server to operate, no cloud, no distributed anything** — it's an async HTTP client with a dictionary (the ledger) and a comparison function. It maps directly onto your AdlerQA work, so your "why did you build this?" answer is a lived story with 12 real findings behind it. The real risks are (a) scope creep (spec-less import, dependency chains, BFLA — all deferrable) and (b) the safety obligations of a tool that creates data (addressed head-on in §13). Both are managed by the roadmap.

---

# 2. What form factor should WrongDoor be?

| Form factor | Dev difficulty | Security | UX | Buildable alone? | Portfolio value | Demoability | Teaches you |
|---|---|---|---|---|---|---|---|
| **CLI tool** | Low–Med | High (you control every request) | Ideal for devs & CI | **Yes** | High (security tools are CLIs) | Excellent (drops into CI) | Async HTTP, auth, the core engine |
| Desktop app | High | Medium | Nicer for non-devs | Risky (GUI eats time) | Medium | Good | GUI plumbing (low security value) |
| Windows/Linux exe | Low (package the CLI) | High | Same as CLI | Yes | Medium | Good | Packaging only |
| Web application | High | Medium/Low (auth, sessions, hosting) | Best visuals | Hard alone | High *if* polished | Great visuals | Full-stack (dilutes focus) |
| Browser extension | Medium | Medium | Niche | Maybe | Low (wrong shape) | Poor | Irrelevant skills |
| Local agent | High | Complex | Invisible | Hard | Medium | Poor | Wrong domain |
| SaaS | Very high | You'd hold clients' credentials + hit their live APIs — serious liability | Best reach | **No** | High but unrealistic | Hard | Ops, not security depth |
| Self-hosted app | High | Medium | Good | Hard alone | Medium | Medium | Deployment |
| **Hybrid: CLI core + single-file HTML report + GitHub Action** | Low–Med | High | Great for demos | **Yes** | **Highest** | **Excellent** | The engine *and* CI integration |

**Recommendation — stated decisively:**

**Build WrongDoor as a CLI tool, with a single-file HTML report and a GitHub Action as the two secondary surfaces, because:** the CLI is where the authorization-testing engine lives and where you keep total control over every request sent to the target; it drops straight into CI, which is the demo that lands (a red check caused by a real IDOR); and it is the only shape you can fully build and fully explain alone. The HTML report is a pure consumer of the findings (attachable to a PR). The GitHub Action is a thin wrapper that runs the CLI and uploads SARIF. 

Do **not** build it as SaaS: a hosted service that stores customers' identity credentials *and* fires create/delete requests at their live APIs is a liability you should not take on for a student project. Keep it local, keep it read-mostly against systems you own.

---

# 3. Architecture

The architecture is a **staged pipeline with one live side-effecting phase (seeding + execution)**. Data flows one direction; there is exactly one long-lived structure per run (the ownership ledger, in memory) and no external service in the MVP. The only network I/O is WrongDoor → the target API.

```text
                          ┌───────────────────────────────┐
                          │      You (developer / CI)       │
                          └───────────────┬────────────────┘
                                          │  wrongdoor run config.yaml --spec openapi.json
                                          ▼
        ┌─────────────────────────────────────────────────────────────────┐
        │                          CLI  (Typer)                            │
        │      parse args · pick reporters · enforce --fail-on threshold   │
        └───────────────┬─────────────────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────┐     ┌───────────────────────────────┐
        │        CONFIG LOADER       │     │   STATIC SANITY PASS (bonus)   │
        │  read+validate config.yaml │────▶│  typos, dangling refs, cycles  │
        │  (Pydantic)                │     │  runs BEFORE any live request  │
        └───────────────┬───────────┘     └───────────────────────────────┘
                        │  validated config + identities + ownership policy
                        ▼
        ┌───────────────────────────┐     ┌───────────────────────────────┐
        │      SPEC IMPORTER         │     │        SAFETY GUARD            │
        │  OpenAPI → operation list  │     │  host allowlist · --confirm    │
        │  (method, path, params)    │     │  own-target · dry-run · rate   │
        └───────────────┬───────────┘     └───────────────┬───────────────┘
                        │                                  │ gates all live I/O
                        ▼                                  ▼
        ┌───────────────────────────┐        ═══════════ LIVE TARGET API ═══════════
        │      IDENTITY MANAGER      │───auth──▶  (a running instance you own)
        │  authenticate each identity│◀──token──
        │  hold a session per identity        ▲              ▲            ▲
        └───────────────┬───────────┘         │ create       │ create     │ replay
                        │ authed sessions      │ as Alice     │ as Bob     │ as non-owners
                        ▼                      │              │            │
        ┌───────────────────────────┐         │              │            │
        │          SEEDER            │─────────┴──────────────┘            │
        │  run create-ops as each id │  captures returned object IDs       │
        │  + capture owner's view    │                                     │
        └───────────────┬───────────┘                                     │
                        ▼                                                  │
        ┌───────────────────────────┐   ◄── THE CORE: ground truth        │
        │      OWNERSHIP LEDGER      │       object_id → owner             │
        │  {obj → owner, canon body} │       + canonical owner-response    │
        └───────────────┬───────────┘                                     │
                        ▼                                                  │
        ┌───────────────────────────┐                                     │
        │      MATRIX PLANNER        │  (operation × identity × object)    │
        │  minus self-owned combos   │  = list of cross-identity requests  │
        └───────────────┬───────────┘                                     │
                        ▼                                                  │
        ┌───────────────────────────┐                                     │
        │      ASYNC EXECUTOR        │─────replay planned requests─────────┘
        │  httpx + asyncio           │  rate-limited · retry · concurrent
        │  as the acting identity    │
        └───────────────┬───────────┘
                        │  (planned_request, observed_response)
                        ▼
        ┌───────────────────────────┐   ◄── THE ORACLE
        │      VERDICT ENGINE        │  expected(policy) vs observed
        │  + body-diff vs owner canon│  → PASS · VIOLATION · INCONCLUSIVE
        └───────────────┬───────────┘
                        │  findings (each with the request pair as evidence)
                        ▼
        ┌───────────────────────────┐
        │       RISK SCORER          │  deterministic: sensitivity × access
        │                            │  type × cross-tenant × method
        └───────────────┬───────────┘
              ┌─────────┼───────────┬─────────────┐
              ▼         ▼           ▼             ▼
         ┌────────┐ ┌───────┐  ┌────────┐   ┌──────────────┐
         │Terminal│ │ JSON  │  │ SARIF  │   │  HTML report │
         │ (Rich) │ │       │  │ +JUnit │   │  + curl pairs│
         └────────┘ └───────┘  └────────┘   └──────────────┘
```

**Where each concern lives:**
- **Analysis happens** in the VERDICT ENGINE, over `(planned_request, observed_response)` pairs plus the ledger. Nowhere else decides "leak or not."
- **Authorization data comes from reality** — the live target's actual responses — anchored to ground truth captured by the SEEDER into the LEDGER.
- **Results are stored** as output files (JSON/SARIF/JUnit/HTML). No database in the MVP; the ledger is in-memory for the run. (Optional SQLite for run history later.)
- **The UI fits** at the very end, as a pure consumer of findings.
- **The security boundaries** are two: (1) the CONFIG LOADER + STATIC PASS treat the YAML as untrusted input; (2) the SAFETY GUARD sits between all of WrongDoor and the network, so no live request leaves without passing the allowlist/confirmation/rate checks.

---

# 4. Tech stack (the smallest sensible set)

For each: what it is · why WrongDoor needs it · why this choice · alternatives/trade-offs · what to learn · where it appears.

### Language — **Python 3.12**
- **What/why:** the substrate for everything; your strongest language and the security-tooling lingua franca, so you keep control and recruiters recognize it.
- **Alternatives:** Go (single-binary, great concurrency — but you don't know it, and its speed is irrelevant at test scale); Rust (overkill). Neither buys you anything here.
- **Learn:** type hints, dataclasses, and — the one real gap — `asyncio` fundamentals.
- **Appears in:** all of it.

### Async HTTP — **httpx + asyncio (with anyio)**
- **What:** an async-capable HTTP client; asyncio runs many requests concurrently.
- **Why needed:** the test matrix is *thousands* of independent requests (operations × identities × objects). Sequential would be unusably slow; concurrency is intrinsic to the problem, not decoration.
- **Why this one:** httpx is the modern client with first-class async, HTTP/2, connection pooling, and per-identity `Client` objects (perfect for holding a session per identity). asyncio is stdlib.
- **Alternatives:** `requests` (sync only — wrong for a matrix), `aiohttp` (fine, but httpx's API is cleaner and its sync/async parity helps testing). 
- **Learn:** `async`/`await`, `asyncio.gather`, semaphores for concurrency limits, why you pool connections per identity.
- **Appears in:** IDENTITY MANAGER, SEEDER, ASYNC EXECUTOR.

### Config/models — **Pydantic v2**
- **What:** turns untrusted YAML/JSON into validated typed objects with good error messages, and emits a JSON Schema for free (editor autocomplete for `config.yaml` = adoption).
- **Why needed:** the config is untrusted text describing identities, auth, and ownership policy; validate it once at the boundary, trust it after.
- **Alternatives:** hand-written validation (tedious, error-prone); dataclasses (no free schema).
- **Learn:** Pydantic models, validators, `model_validate`, discriminated unions (for the different auth types).
- **Appears in:** CONFIG LOADER, the DSL schema, the static sanity pass.

### Spec parsing — **`openapi-core` + `prance` (for `$ref` resolution)**
- **What:** parse an OpenAPI 3.x document into the list of operations (method + templated path + parameters + which params are object IDs).
- **Why needed:** WrongDoor needs to know the target's operations to seed and replay them; OpenAPI is the standard description.
- **Why these:** `$ref` resolution and spec validation are solved, subtle problems — don't reimplement them.
- **Alternatives:** parse the spec yourself (a trap — specs are gnarly); require the user to list operations manually (fine as a fallback for spec-less APIs, Phase 5).
- **Learn:** the OpenAPI operation/parameter model; path templating (`/invoices/{id}`).
- **Appears in:** SPEC IMPORTER.

### CLI — **Typer + Rich**
- **What:** Typer builds the CLI from typed functions; Rich prints readable, colored findings and progress.
- **Why:** the primary interface is the command line; Rich makes live progress and findings look professional in a demo with near-zero effort.
- **Alternatives:** `argparse` (more boilerplate), `click` (Typer sits on it).
- **Learn:** Typer command/flag mapping; Rich tables and progress bars.
- **Appears in:** CLI, terminal reporter.

### Reporting — **Jinja2 (HTML) + stdlib `json` + hand-written SARIF & JUnit**
- **What:** Jinja2 renders one self-contained HTML report; SARIF (GitHub/IDE-native security format) and JUnit (CI test format) are simple JSON/XML you emit from your findings.
- **Why needed:** humans need the report + `curl` pairs; CI needs SARIF for inline PR annotations and JUnit to treat authz as a test suite.
- **Why these:** Jinja2 needs no JS build step; SARIF/JUnit are the interchange standards (knowing SARIF is itself a resume point) and are just structured text.
- **Learn:** Jinja2 templates; minimal SARIF (`run` → `results` → `locations`); minimal JUnit (`testsuite` → `testcase`/`failure`).
- **Appears in:** REPORTERS.

### Testing — **pytest + Testcontainers + a vulnerable demo API (FastAPI)**
- **What:** pytest runs tests; Testcontainers spins up the demo API in Docker during tests; the demo API (built with FastAPI, which you already know) is a deliberately-vulnerable multi-tenant target with *planted* BOLA bugs.
- **Why needed:** correctness of a security tool is the whole game; you need a **live target with a known answer** to prove WrongDoor finds exactly the planted bugs and nothing else.
- **Why these:** Testcontainers gives real integration tests against a real running app; FastAPI lets you write the vulnerable target fast and reuse skills.
- **Learn:** pytest fixtures, Testcontainers lifecycle, writing a tiny multi-tenant API.
- **Appears in:** `tests/`, `examples/vulnerable-api/`.

### Packaging / CI — **`uv` (or pip) + `pyproject.toml`; GitHub Actions; PyPI + Docker later**
- **What:** dependency management, packaging (`pip install wrongdoor`), and CI that runs tests and dogfoods WrongDoor against the demo app.
- **Learn:** virtual environments, `pyproject.toml`, a basic Actions workflow.
- **Appears in:** repo root, `.github/workflows/`, `action/`.

### Deliberately **NOT** in the stack (and why)
- **No database** in the MVP — the ledger is an in-memory dict for the run; findings are files. (Optional SQLite for run history later.)
- **No Redis/Kafka/queue** — concurrency is handled by asyncio within one process; there is no cross-process work to distribute.
- **No Kubernetes/microservices/cloud** — one process, one target. See §19.
- **No ML framework** — the verdict is deterministic comparison, not a model.
- **LLM: optional and cosmetic only** (see §10), an HTTP call, not a trained dependency.

---

# 5. Component walkthrough (as if you're about to build each)

For each: what · why · inputs · outputs · internal logic · dependencies · security notes. Then the call chain.

### 5.1 CLI
- **What/why:** entry point (`wrongdoor run`, `wrongdoor lint`, `wrongdoor report`); wires the pipeline; owns the `--fail-on` exit code that makes CI fail. Contains no analysis.
- **Inputs:** args (config path, spec path, target base URL, reporters, severity threshold, `--dry-run`, `--confirm-own-target`).
- **Outputs:** exit code + reporter output.
- **Security notes:** never `eval` args; the target URL and confirmation flags are checked by the Safety Guard before any live call.

### 5.2 Config Loader
- **What/why:** reads `config.yaml`, validates it into typed objects (identities, auth methods, ownership policy, target settings). Fails fast with clear errors.
- **Inputs:** a file path. **Outputs:** a validated `Config` (or a precise error).
- **Internal logic:** `yaml.safe_load` → `Config.model_validate`. Enforce caps (max identities, max operations) to bound run size.
- **Security notes:** the untrusted-input boundary. `safe_load` only; never store plaintext secrets *in* the config — auth references env vars / a secrets file (see §13).

### 5.3 Static Sanity Pass (bonus, pre-flight)
- **What/why:** a cheap offline linter that runs *before* any live request: dangling identity references, an ownership rule for a resource no operation creates, an auth type with missing fields, a cycle in declared resource-creation dependencies, obvious typos. Its value is catching config mistakes before you waste a live run and, worse, before you create junk data in the target.
- **Inputs:** the validated `Config` (+ imported operations). **Outputs:** lint warnings/errors; can block the run on errors.
- **Internal logic:** reference checks + a small cycle detection over the resource-dependency declarations (DFS). *This is the only place graph traversal appears, and it's a bonus, not the core.*
- **Security notes:** pure/offline; no I/O beyond reading config.

### 5.4 Spec Importer
- **What/why:** turns the OpenAPI spec into an operation catalog: for each operation, its method, templated path, parameters, and a classification of which parameters are **object identifiers** (the things that get swapped in a BOLA test) vs. body/query.
- **Inputs:** an OpenAPI file (or, Phase 5, a HAR/Postman/Burp export). **Outputs:** `list[Operation]`.
- **Internal logic:** parse + resolve `$ref`; tag create-operations (usually `POST` returning an ID) vs. access-operations (`GET`/`PUT`/`DELETE` on `/{id}`).
- **Security notes:** the spec is untrusted-ish input too — validate it, cap operation count.

### 5.5 Identity Manager
- **What/why:** authenticates each identity and holds a live authenticated session (an httpx client with the right headers/cookies) per identity; refreshes tokens as needed.
- **Inputs:** identities + auth config from `Config`. **Outputs:** a dict `identity_id → AuthedClient`.
- **Internal logic:** per auth type (bearer token, cookie/session login, API key, OAuth2 client-credentials/password grant), perform the flow, store credentials in memory, attach to the client. Handle 401 → refresh → retry.
- **Dependencies:** httpx, the auth-plugin interface.
- **Security notes:** **secrets live here and only here.** Read from env/secrets file; never log tokens; redact `Authorization` from any diagnostic output.

### 5.6 Seeder
- **What/why:** the ground-truth builder. For each create-operation, it runs the operation **as each identity**, reads the created object's ID from the response, and records `object_id → owning_identity`. It also captures the **owner's canonical view** of the object (the create response body, and a follow-up `GET` as the owner) so the verdict engine has something to match against later.
- **Inputs:** authed clients, create-operations, ownership policy. **Outputs:** entries written to the OWNERSHIP LEDGER.
- **Internal logic:** for op in create-ops: for id in identities: send create as id (with valid sample body derived from the spec's schema); extract the new object id (from `Location` header, response body `id` field, or a configured JSONPath); store `(object_id, owner=id, canonical_body)`. 
- **Dependencies:** httpx, spec (for example bodies), Safety Guard.
- **Security notes:** **this phase writes real data.** It must be gated by the Safety Guard (allowlist + confirmation), bounded (don't create thousands of objects by accident), and ideally track created IDs so a `--cleanup` can delete them afterward (in a test env).

### 5.7 Ownership Ledger
- **What/why:** the one core data structure — the record of truth. `object_id → {owner, resource_type, canonical_body}`. Everything the verdict engine concludes rests on this being correct.
- **Inputs:** writes from the Seeder. **Outputs:** lookups for the Planner and Verdict Engine.
- **Internal logic:** an in-memory dict for the run (optionally persisted to SQLite for history/debugging).
- **Security notes:** contains real (possibly sensitive) object data → treat as sensitive; redact in any output.

### 5.8 Matrix Planner
- **What/why:** builds the list of tests to run: for each access-operation and each object in the ledger, plan a request performed by **each identity that is not the owner** (and, per policy, not otherwise authorized). This is the Cartesian product minus the self-owned/authorized cells.
- **Inputs:** ledger + operations + ownership policy. **Outputs:** `list[PlannedRequest]`, each = (acting_identity, operation, target_object, expected_verdict).
- **Internal logic:** for obj in ledger: for identity not owner(obj): for op in access-ops applicable to obj's type: expected = policy.expected(identity, obj, op) → append PlannedRequest.
- **Security notes:** destructive operations (`DELETE`, `PUT`) are flagged and, by default, ordered after reads or gated behind a flag (§13).

### 5.9 Async Executor
- **What/why:** sends the planned requests concurrently as the acting identity, with a concurrency limit, rate limiting, timeouts, and retries. Records the observed response (status, headers, body).
- **Inputs:** planned requests + authed clients. **Outputs:** `list[(PlannedRequest, ObservedResponse)]`.
- **Internal logic:** an asyncio worker pool bounded by a semaphore; each task uses the acting identity's client; capture status + (size-capped) body.
- **Security notes:** conservative default concurrency and rate so WrongDoor can't accidentally DoS the target; respect `--dry-run` (plan and print, send nothing).

### 5.10 Verdict Engine (the oracle)
- **What/why:** decides, for each result, whether authorization held, broke, or is inconclusive — and, crucially, *confirms* a leak by matching the body against the owner's canonical object. Detailed algorithm in §7/§9/§12.
- **Inputs:** `(PlannedRequest, ObservedResponse)` + ledger. **Outputs:** `Finding`s (with evidence) and pass/inconclusive records.
- **Internal logic:** compare expected vs observed status class; on a non-owner `2xx`, run body-diff against `canonical_body` (normalizing volatile fields); classify as PASS / VIOLATION / INCONCLUSIVE.
- **Security notes:** pure function of its inputs — no I/O — so it's trivially testable and can't become an injection vector. **This is the code you must own completely.**

### 5.11 Risk Scorer / Explainer / Reporters
- As in the pipeline: deterministic severity (§9), template explanation (+ optional LLM reword, §10), and serialization to terminal/JSON/SARIF/JUnit/HTML with redaction by default (§13).

### The complete call chain (narrate this in your viva)

```text
You run:  wrongdoor run config.yaml --spec openapi.json --target https://staging.myapp.test --fail-on high

CLI
 └─ ConfigLoader.load("config.yaml")              → Config           (untrusted → trusted here)
     └─ [optional] StaticSanityPass.check(Config) → warnings         (offline pre-flight)
         └─ SpecImporter.load("openapi.json")     → [Operation...]
             └─ SafetyGuard.assert_allowed(target, confirmed)        (gate before ANY live call)
                 └─ IdentityManager.authenticate(Config)  → {id → AuthedClient}   (LIVE)
                     └─ Seeder.seed(create_ops, clients)  → writes OwnershipLedger (LIVE, creates data)
                         └─ MatrixPlanner.plan(ledger, ops, policy) → [PlannedRequest...]
                             └─ AsyncExecutor.run(planned, clients)  → [(req, observed)...]  (LIVE)
                                 └─ for (req, obs): VerdictEngine.judge(req, obs, ledger) → Finding|Pass
                                     └─ RiskScorer.score(finding)     → severity band
                                         └─ Explainer.explain(finding)→ text (+ optional LLM)
                                             └─ Reporters.emit(...)   → terminal + JSON + SARIF + JUnit + HTML
CLI
 └─ exit(1) if any finding ≥ --fail-on            (breaks the CI build)
 └─ [optional] Seeder.cleanup(created_ids)        (delete seeded objects in the test env)
```

Every arrow is a function call passing typed objects; the only network I/O is the three phases marked **LIVE**, all behind the Safety Guard. That's why you can hold the whole thing in your head.

---

# 6. The core authorization/security model

The dynamic design's "model" is not a graph of intentions — it's a small set of facts about identities and a **policy of expected access**, anchored to ground truth the Seeder discovers at runtime.

### The entities

| Concept | How WrongDoor represents it |
|---|---|
| **Identity** | A principal WrongDoor can authenticate as: `{id, auth: {...}, attributes: {role, tenant, ...}}`. Identities are the actors in the test. |
| **Auth method** | Per identity: bearer token, cookie/session login (username+password → session), API key, or OAuth2 (client-credentials / password grant), with token refresh. |
| **Operation** | From OpenAPI: `{method, path_template, params, kind: create|access}`, with object-identifier params tagged. |
| **Resource / object** | A concrete instance created during seeding: `{object_id, resource_type, owner_identity, canonical_body}`. **Discovered, not declared.** |
| **Ownership** | The `object_id → owner_identity` mapping in the ledger — captured by construction (whoever created it owns it). |
| **Access policy (expected verdict)** | The rule that says, for a given (identity, object, operation), whether access should be **allowed** or **denied**. MVP default: *only the owner may access an object* (plus optional role rules: e.g. an `admin` identity may access all; members of the same `tenant` may/‑may‑not, per config). |
| **Trust boundary** | Expressed via identity `attributes` (e.g. `tenant`). A cross-tenant access that succeeds is a boundary break. |

### The internal data model (what actually lives in memory)
1. **Identity registry:** `{identity_id → AuthedClient + attributes}`.
2. **Operation catalog:** `[Operation]` from the spec.
3. **Ownership ledger:** `{object_id → {owner, resource_type, canonical_body}}` — the ground truth.
4. **Access policy:** a small, explicit function `expected(identity, object, operation) → ALLOW | DENY`, driven by config (owner-only by default; extendable with role/tenant rules).
5. **Test matrix:** `[PlannedRequest]` = the Cartesian product minus authorized cells.

### Why this beats a static model *and* beats heuristic dynamic tools
- **Against static YAML:** WrongDoor doesn't trust a description of who *should* own what — it *observes* who really owns what by creating the objects, so it measures the real app, drift included.
- **Against Burp Autorize / Auth Analyzer (heuristic):** those infer "leak" from response *similarity* between two sessions — noisy on dynamic content, and limited to ~two identities in practice. WrongDoor knows the *true* owner and the object's *actual* content, so a leak is confirmed by a body match against ground truth, across *N* identities, deterministically.

### What you need to learn for this section
HTTP auth flows (bearer/JWT, cookie sessions, OAuth2 grants, refresh); the OpenAPI operation/parameter model; and the idea of an *oracle* (a decision procedure that says pass/fail). No graph theory is required for the core — the intellectual weight is in the seeding trick and the verdict logic.

---

# 7. What WrongDoor detects (start with BOLA, done well)

Each: the problem · a realistic example · how WrongDoor detects it · the algorithm · the evidence · remediation. Ordered by build priority.

### D1 — Broken Object Level Authorization (BOLA / IDOR) — **the flagship**
- **Problem:** an endpoint returns/modifies an object based on an ID in the request without checking that the caller owns or may access that object. OWASP API Security #1.
- **Example:** `GET /invoices/{id}` returns any invoice by ID. Alice owns `invoice/1001`; Bob (different user/tenant) requests it and receives Alice's invoice with a `200`.
- **Detection:** the Seeder recorded `1001 → Alice` and Alice's canonical invoice body. The Planner schedules "Bob `GET /invoices/1001`". Expected: DENY. Observed: `200` + body. The Verdict Engine body-matches Bob's response against Alice's canonical body → **confirmed leak**.
- **Algorithm:** for each object, replay each access-op as each non-owner; on a non-owner `2xx`, confirm via body-diff (below). No traversal — it's a matrix sweep + comparison.
- **Evidence:** the **reproducible request pair** — Alice's authenticated `GET` (canonical), and Bob's authenticated `GET` returning the same object — plus a redacted body diff showing the overlap.
- **Remediation:** add an ownership/tenancy check on the object lookup (`WHERE owner = current_user` / policy check) on that endpoint.

### D2 — Broken Function Level Authorization (BFLA) — vertical
- **Problem:** a low-privilege identity can call an operation reserved for higher privilege (admin-only endpoints, methods).
- **Example:** `DELETE /users/{id}` or `GET /admin/reports` succeeds for a normal user.
- **Detection:** mark operations as privileged (via config or an `admin`-only tag); replay them as non-privileged identities; expected DENY, observed `2xx`/success → finding. (For state-changing ones, confirm the effect cautiously, e.g. the object is gone / changed — test env only.)
- **Algorithm:** matrix sweep of privileged operations across under-privileged identities; verdict on status + optional effect check.
- **Evidence:** the request as a normal user succeeding on an admin operation.
- **Remediation:** enforce role checks at the function/route level.

### D3 — Missing/broken authentication on protected operations
- **Problem:** an endpoint that should require auth serves data with no (or an invalid) token.
- **Example:** `GET /invoices/{id}` returns data when called with **no** `Authorization` header.
- **Detection:** replay access-operations with an *unauthenticated* client and with a *tampered/expired* token; expected DENY (`401`), observed `2xx` → finding.
- **Algorithm:** a special "null identity" row in the matrix.
- **Evidence:** the unauthenticated request returning protected data.
- **Remediation:** enforce authentication middleware on the route.

### D4 — Mass assignment / privilege-field tampering *(bonus, Phase 5)*
- **Problem:** a create/update accepts fields it shouldn't (e.g. `is_admin`, `owner_id`, `tenant`), letting a user grant themselves privileges or reassign ownership.
- **Example:** `PATCH /users/me {"role":"admin"}` succeeds; or `POST /invoices {"owner_id": <someone else>}`.
- **Detection:** during seeding/replay, inject known-sensitive fields into request bodies as a normal identity; verify via a follow-up read whether the field took effect.
- **Algorithm:** targeted field injection + effect confirmation (read-back).
- **Evidence:** the tampered request + the read-back showing the elevated field.
- **Remediation:** allow-list writable fields (schema binding), ignore/deny protected fields.

**The body-diff sub-algorithm (shared by D1/D4 — the part that makes findings *confirmed*):**
```
confirm_leak(observed_body, canonical_body):
    a = normalize(observed_body)      # drop volatile fields (timestamps, etags, last_seen…)
    b = normalize(canonical_body)     #   (which fields are volatile is configurable)
    # containment: does the owner's identifying data appear in the non-owner's response?
    return identifying_fields(b) ⊆ a  # e.g. the object id + a stable unique field match
```
If a non-owner gets `2xx` but the body does **not** contain the owner's object data (e.g. a correctly-filtered empty result, or generic content), WrongDoor records **INCONCLUSIVE-allow for review**, *not* a confirmed leak. That restraint — refusing to cry "BOLA" without a body match — is exactly what keeps false positives near zero and is the maturity signal to highlight.

**Why this set:** D1 is the flagship and the one you must nail. D2/D3 reuse the same matrix machinery with different expected verdicts, so they're cheap add-ons. D4 is a bonus that shares the confirm-by-read-back idea. Together they cover OWASP API #1 (BOLA), #5 (BFLA), #2 (broken auth), and #6 (mass assignment) — a credible, focused set, not a scanner trying to do everything.

---

# 8. Where the authorization data comes from

**It comes from the live target's real responses — that's the entire point.** WrongDoor needs two inputs to talk to that target:

1. **`config.yaml`** — you author this: the identities, their auth methods and attributes (role/tenant), the target base URL, the access policy (owner-only by default), and seeding settings.
2. **An OpenAPI spec** — describes the operations. If the target has one, WrongDoor imports it directly. (Spec-less targets: Phase 5 adds HAR/Burp/Postman import so you can drive it from recorded traffic.)

WrongDoor then *discovers* the authorization facts at runtime by seeding. You are not describing who owns what — WrongDoor finds out by creating the objects.

**For development and testing, build a controlled target you own: the intentionally-vulnerable demo API.** A small FastAPI multi-tenant app (e.g. an invoicing API) with several identities, some correctly-secured endpoints, and **planted BOLA/BFLA bugs on specific endpoints**. This is your known-answer harness: you know exactly which endpoints are vulnerable, so you can assert WrongDoor finds those and *only* those. It's also your demo target. This recovers the determinism/testability that made the static approach attractive — but against a *real running app*, which is the honest thing to test.

**Then, real targets (carefully, systems you own or are authorized to test):** staging instances of your own projects; a CTF/lab API; a bug-bounty target *with an explicit safe-harbor policy and test-account permission*. Never production, never third-party without written authorization (§13).

Recommendation: **build the vulnerable FastAPI demo first** (it's your test oracle and your demo), then point WrongDoor at a staging instance of one of your own real apps to prove it works beyond the demo.

---

# 9. Engine design (each stage explained)

**Recommendation: a black-box, dynamic, differential engine with a deterministic verdict oracle.** Not static, not LLM-driven. Here is every stage of the pipeline you asked about, mapped to this design:

```text
Raw config + OpenAPI spec              (what you provide)
        ↓  CONFIG LOADER (+ optional STATIC SANITY PASS): validate, catch typos/cycles offline
Validated config + operation catalog
        ↓  IDENTITY MANAGER: authenticate each identity (LIVE)
Authenticated sessions (per identity)
        ↓  SEEDER: create objects as each identity (LIVE) → record ground truth
Ownership ledger  {object → owner, canonical body}
        ↓  MATRIX PLANNER: (operation × identity × object) − authorized cells
Test matrix  [PlannedRequest(actor, op, object, expected_verdict)]
        ↓  ASYNC EXECUTOR: replay across identities (LIVE), capture responses
Observed results  [(request, response)]
        ↓  VERDICT ENGINE: expected vs observed + body-diff vs canonical
Security findings  (confirmed leaks, with the request pair as evidence)
        ↓  RISK SCORER: deterministic severity
Risk / severity  (Critical/High/Medium/Low + factors)
        ↓  EXPLAINER: template sentence (+ optional LLM reword)
Explanation  (why it's a finding, + the reproducible curl pair)
```

**Stage details (the two that carry the intellectual weight):**

- **Seeding → ledger (ground truth by construction):** the reason WrongDoor can *confirm* rather than *guess*. Because Alice created `invoice/1001`, WrongDoor knows with certainty that `1001` belongs to Alice and knows what Alice's invoice actually contains. Capture the owner's canonical view here (create response + owner `GET`), normalizing which fields are volatile.

- **Verdict engine (the oracle) — the precise decision procedure:**
  ```
  judge(request, response, ledger):
     obj   = request.target_object
     owner = ledger[obj].owner
     exp   = request.expected_verdict            # ALLOW or DENY (from policy)

     if response.status in 5xx:                  return INCONCLUSIVE("server error")
     if exp == ALLOW:
         return PASS if response.status in 2xx else BROKEN("legit access denied")
     # exp == DENY (actor is a non-owner / unauthorized):
     if response.status in (401, 403):           return PASS("correctly denied")
     if response.status == 404:
         # we KNOW the object exists (we created it) → 404 to a non-owner is acceptable
         # info-hiding. (404 to the OWNER would be BROKEN, handled under ALLOW.)
         return PASS("denied via not-found / info hiding")
     if response.status in 2xx:
         if confirm_leak(response.body, ledger[obj].canonical_body):
                                                 return VIOLATION("confirmed BOLA")   # ← finding
         else:                                   return INCONCLUSIVE("2xx to non-owner, no body match — review")
     return INCONCLUSIVE("unexpected status")
  ```
  Four honest states: **PASS** (secure), **VIOLATION** (confirmed leak, with evidence), **BROKEN** (app denies legitimate access — a bug, reported separately, never counted as a security pass), **INCONCLUSIVE** (needs a human). A tool that collapses these — e.g. treating every `2xx` as a leak, or every `500` as a pass — is exactly the noisy tool you're trying to beat.

- **Risk scoring (deterministic rubric):**
  `severity = f(resource_sensitivity, access_type, cross_tenant, method)`, e.g.:
  - cross-tenant read of a `high`-sensitivity object → **Critical**;
  - same-tenant read of a `high` object by a non-owner → **High**;
  - write/delete (mutation) generally one band above the equivalent read;
  - low-sensitivity read → **Medium/Low**.
  Every number is documented and reconstructable by hand — so you can say *"Critical because it's a cross-tenant leak of financial data via a GET,"* not *"the model scored it 0.87."*

---

# 10. AI/LLM usage — where it belongs (and where it must not)

**Verdict: the LLM is optional, cosmetic, downstream, and off by default. The engine confirms and scores every finding without it.**

Legitimate, bounded uses (all post-finding):
1. **Explaining a finding in natural language** — reword the deterministic template ("Bob accessed Alice's invoice 1001 cross-tenant via GET") into friendlier prose. The finding and its `curl` evidence exist regardless.
2. **Drafting remediation prose** — turn "add ownership check on `GET /invoices/{id}`" into a short paragraph, optionally with a code sketch for the target's framework. You still identify the endpoint/fix deterministically.
3. **(Stretch) Suggesting seeding bodies** — for a create-operation whose schema is under-specified, an LLM could propose a plausible sample request body. But this is *input generation*, not a security decision, and must be validated against the schema before use.

Where the LLM must **never** be: deciding whether a response is a leak (that's the body-diff against ground truth), computing severity, or interpreting authorization semantics.

Hard rule in code: the Explainer receives an *already-final, already-confirmed* Finding and returns a *string* that is never parsed back into logic. Disable the LLM and every finding, verdict, score, and `curl` pair is byte-for-byte identical — only the prose changes. State this explicitly in your report; it's the line between "serious security tool" and "AI wrapper," and evaluators will probe it.

Privacy (see §13): the LLM path would send real request/response snippets (possibly containing real data) to a third party — so it's opt-in, warns loudly, and redacts by default (send field *names/shapes*, not values).

---

# 11. User interface

**Recommendation: CLI first (the product), a single-file HTML report second, a GitHub Action third. No desktop GUI, no SPA.**

**CLI (MVP):**
- `wrongdoor run config.yaml --spec openapi.json --target URL` → live progress (authenticating N identities… seeding… executing 3,412 checks…) then a Rich summary: counts by severity, each finding as a panel with the two requests.
- `wrongdoor lint config.yaml` → the static sanity pass alone (fast, offline).
- Flags: `--format`, `--fail-on high`, `--dry-run`, `--confirm-own-target`, `--cleanup`, `--explain`.

**HTML report (Phase 4):** one self-contained file. Header with severity counts; per-finding card containing the title, severity + the factors that produced it, the **reproducible `curl` pair** (owner's request that defines the canonical object + the non-owner's request that leaked it), a redacted body-diff highlighting the overlapping fields, and the remediation. Attachable to a PR or email.

**GitHub Action (Phase 4):** runs the CLI against a staging target spun up in the workflow, uploads SARIF (so findings annotate the PR inline), and fails the check above the threshold. This is the demo that lands.

**What each surface shows:** severity summary; per-finding request pair + body-diff evidence; the acting identity and the victim object/owner; remediation; and a stable finding fingerprint (operation + object-type + actor-role) so CI distinguishes "new finding" from "known." No graph visualization is needed in this design — the evidence *is* two HTTP requests, which is more convincing than any diagram.

Keep v1 to CLI + terminal + JSON + SARIF. HTML and the Action are the polish that make the viva shine.

---

# 12. End-to-end worked example (with internals)

**Target:** a running multi-tenant invoicing API at `https://staging.myapp.test`. **config.yaml** (trimmed):
```yaml
target:
  base_url: https://staging.myapp.test
  allow: [staging.myapp.test]          # safety allowlist
identities:
  - id: alice
    attributes: {tenant: A}
    auth: {type: login, url: /auth/login, username: alice, password_env: ALICE_PW}
  - id: bob
    attributes: {tenant: B}
    auth: {type: login, url: /auth/login, username: bob, password_env: BOB_PW}
policy:
  rule: owner_only            # only the creating identity may access an object
operations_from: openapi.json # POST /invoices (create), GET /invoices/{id} (access)
```

**1. Collect / validate.** Config loader validates; static sanity pass finds no dangling refs or cycles. Spec importer yields `POST /invoices` (create) and `GET /invoices/{id}` (access, `id` = object param).

**2. Authenticate.** Identity manager logs in Alice and Bob (passwords from env vars `ALICE_PW`/`BOB_PW`, never from the file), obtaining a session cookie/token per identity → two authed httpx clients.

**3. Seed (build ground truth).** Safety guard confirms `staging.myapp.test` is allowlisted and `--confirm-own-target` was passed.
- As Alice: `POST /invoices {amount: 500, ...}` → `201`, body `{"id": 1001, "amount": 500, ...}`. Ledger: `1001 → {owner: alice, type: invoice}`. Owner `GET /invoices/1001` → canonical body captured.
- As Bob: `POST /invoices {...}` → `201`, `id: 2002`. Ledger: `2002 → {owner: bob}`, canonical captured.

**4. Plan the matrix.** For `GET /invoices/{id}`: Bob is a non-owner of `1001`; Alice is a non-owner of `2002`. Planned: `Bob GET /invoices/1001 (expect DENY)`, `Alice GET /invoices/2002 (expect DENY)`. (Self-owned cells excluded.)

**5. Execute (live).** Async executor, as Bob's client: `GET /invoices/1001`. Observed: `200` + body `{"id":1001,"amount":500,...}`.

**6. Judge (the oracle).** `expected = DENY`. Status `200` → run `confirm_leak(Bob_body, canonical_1001)`: normalize (drop `created_at`); Alice's identifying fields (`id:1001`, unique `amount:500` + line items) are contained in Bob's response → **match** → **VIOLATION (confirmed BOLA)**. (Alice→2002 returned `403` → PASS.)

**7. Finding object:**
```json
{
  "id": "WD-BOLA-GET_invoices_id-crosstenant",
  "type": "BOLA",
  "actor": {"identity": "bob", "tenant": "B"},
  "victim": {"object": "invoice/1001", "owner": "alice", "tenant": "A"},
  "operation": "GET /invoices/{id}",
  "evidence": {
    "canonical_request":  "GET /invoices/1001  (as alice)  → 200",
    "attack_request":     "GET /invoices/1001  (as bob)    → 200",
    "body_match": ["id", "amount", "line_items"]
  }
}
```

**8. Score.** Cross-tenant (`A`≠`B`) read of a `high`-sensitivity financial object via `GET` → **Critical**, with those factors recorded.

**9. Explain (template):** *"Identity `bob` (tenant B) successfully read `invoice/1001`, owned by `alice` (tenant A), via `GET /invoices/{id}`. The response contained Alice's invoice data (id, amount, line_items), confirming a cross-tenant Broken Object Level Authorization leak. Severity: Critical."* (LLM, if enabled, only prettifies this.)

**10. Report + remediate.** Terminal panel + HTML card show the two `curl`s side by side and the matched fields (values redacted). Remediation: *"`GET /invoices/{id}` must verify the invoice belongs to the caller's tenant/user before returning it (e.g. `WHERE id = :id AND tenant = current_tenant`)."* Optional `--cleanup` deletes seeded invoices `1001`/`2002` from staging.

That's the whole tool in one trace: config → auth → seed (ground truth) → matrix → live replay → body-matched verdict → confirmed finding → evidence → fix. Nothing hidden, nothing heuristic.

---

# 13. Security of WrongDoor itself

This tool **authenticates as real users, creates real data, and fires cross-identity requests at a live API.** That makes its own security posture central — and a rich thing to discuss in a viva.

- **Untrusted input = `config.yaml` and the OpenAPI spec.** `yaml.safe_load` only; validate with Pydantic; cap identities/operations/objects to bound a run; reject malformed specs. The static sanity pass adds a cheap offline guard.
- **Secrets & credentials (front and center here):** identities have passwords/tokens. Read them from **environment variables or a `.gitignore`d secrets file**, referenced by name in the config (`password_env: ALICE_PW`) — **never inline in the YAML**, never logged, never in reports. Redact `Authorization`, `Cookie`, and `Set-Cookie` everywhere. Request the least-privileged test accounts.
- **Destructive-action safety (the big one):** seeding *creates* data and BFLA/mutation tests may *modify or delete* it. Mitigations, all shipped: (1) a **host allowlist** in config — WrongDoor refuses any target not listed; (2) a required `--confirm-own-target` flag; (3) `--dry-run` that plans and prints without sending; (4) mutation/`DELETE` tests **off by default**, opt-in only; (5) tracking of seeded IDs for `--cleanup`; (6) conservative concurrency/rate defaults so it can't DoS the target. Loud docs: *never point this at production or any system you don't own/aren't authorized to test.*
- **SSRF / target control:** the target URL is user-supplied but *authorized by the user* — still, validate it, keep it on the allowlist, and refuse redirects to off-allowlist hosts (a redirect could bounce a request to an internal service).
- **Injection / command execution:** no `eval`/`exec`/`subprocess` with external input; the HTML report **autoescapes** all target-derived strings (an object field containing `<script>` must never execute in the report).
- **Output is highly sensitive:** findings contain real request/response bodies with possibly real PII/financial data. **Redact values by default** (prove the match on field *names*, show values only behind an explicit `--include-bodies`); mark reports sensitive; warn before the LLM path sends anything off-box.
- **Supply chain:** keep the dependency list small (httpx, Pydantic, Typer, Rich, Jinja2, PyYAML, openapi-core — nearly all of it); pin versions; enable Dependabot; generate an SBOM in CI; publish to PyPI via trusted publishing (OIDC). Dogfooding supply-chain hygiene on a security tool is itself a portfolio point.
- **Least privilege & secure defaults:** LLM off, redaction on, mutations off, allowlist required, conservative rate, `--fail-on` explicit.
- **Audit logging:** log *what ran* (target host, identity ids, operation count, findings, seeded-id count) — never secrets or full sensitive bodies.

**Ways WrongDoor could itself become a vulnerability (name these — it's a maturity signal):** (1) credential leakage via logs/reports → redaction + env-only secrets; (2) accidental data destruction or DoS on a target → allowlist + confirmation + mutations-off + rate limits + dry-run; (3) pointing at the wrong/production target → allowlist + explicit confirmation; (4) XSS in the HTML report from hostile response data → autoescaping + JSON-only data to any JS; (5) leaving seeded junk/PII in a shared test env → `--cleanup`; (6) a falsely-clean run giving false assurance → honest docs that WrongDoor tests the operations it's given against the policy it's told, and can't find authz bugs in endpoints absent from the spec.

---

# 14. Development roadmap

Each phase: what to build · concepts learned · tech · difficulty · "done." Ordered so **Phase 3 already yields a demoable, defensible tool** — protect that, because placements compress your time.

### Phase 0 — Prerequisites (1–2 weeks)
- **Build:** throwaway async scripts; a two-endpoint FastAPI toy.
- **Learn:** `asyncio`/httpx (the real gap); HTTP auth flows (bearer/JWT, cookie login, OAuth2 grants, refresh); the OpenAPI operation/parameter model; SARIF/JUnit shapes; the BOLA/BFLA vulnerability classes in depth (you have the field experience — formalize it).
- **Difficulty:** medium.
- **Done when:** you can write an async function that logs into an API two ways and fires 100 concurrent requests with a semaphore, and explain every line.

### Phase 1 — Auth + first live requests (1–2 weeks)
- **Build:** config schema (Pydantic), config loader, identity manager (bearer + cookie login), Safety Guard (allowlist + confirm), and a command that authenticates N identities and hits one endpoint as each.
- **Learn:** validate-at-the-boundary; per-identity sessions; gating live I/O.
- **Tech:** Python, Pydantic, httpx, Typer, Rich, PyYAML.
- **Done when:** `wrongdoor run` authenticates two identities against your toy API and prints each one's response to a shared endpoint.

### Phase 2 — Spec import + seeding + the ledger (1–2 weeks)
- **Build:** OpenAPI importer; the Seeder (create objects as each identity, extract IDs, capture canonical owner view); the Ownership Ledger.
- **Learn:** deriving sample bodies from a schema; extracting created IDs (Location header / body field / JSONPath); *ground truth by construction*.
- **Done when:** after a run, you can print the ledger and it correctly says which identity owns which created object, with the owner's canonical body stored.

### Phase 3 — Matrix + executor + verdict engine (2–3 weeks) ← *first "real project" milestone*
- **Build:** the Matrix Planner, the Async Executor, and the **Verdict Engine** (four-state, with the body-diff confirmer). Build the **vulnerable FastAPI demo API** with planted BOLA (and one correctly-secured endpoint as a false-positive control).
- **Learn:** the oracle; body normalization/containment; distinguishing PASS/VIOLATION/BROKEN/INCONCLUSIVE.
- **Difficulty:** medium–high (this is the core).
- **Done when:** WrongDoor runs against the demo API and reports **exactly** the planted BOLA(s), with the reproducible request pair, and **zero** findings on the secured endpoint — all under pytest + Testcontainers.

### Phase 4 — Reporting + CI (1–2 weeks)
- **Build:** JSON/SARIF/JUnit/HTML reporters (with redaction + `curl` pairs); the GitHub Action; the `--fail-on` gate; the static sanity pass (`wrongdoor lint`).
- **Learn:** SARIF/JUnit; Jinja2; making a bad target turn a CI check red.
- **Done when:** a PR that reintroduces a BOLA into the demo API produces a red GitHub Actions check with an inline SARIF annotation and an attached HTML report.

### Phase 5 — Coverage & realism (1–2 weeks)
- **Build:** more auth types (API key, OAuth2 grants + refresh); BFLA (D2) and unauthenticated (D3) detectors; spec-less import (HAR/Burp/Postman); resource **dependency chains** in seeding (create Org → Project → Invoice).
- **Learn:** creation-dependency ordering; deriving operations from recorded traffic.
- **Done when:** WrongDoor tests a target that needs a create-chain, and catches a BFLA and an unauthenticated-access bug.

### Phase 6 — Hardening + optional extras (1–2 weeks)
- **Build:** the full §13 hardening (secrets, redaction, mutations-off default, cleanup, rate limits, SSRF/redirect guard, autoescaping); optionally the mass-assignment detector (D4) and/or the LLM explainer.
- **Learn:** threat-modeling your own tool.
- **Done when:** WrongDoor safely refuses a non-allowlisted target, never logs a token, redacts report bodies by default, and cleans up seeded data.

### Phase 7 — Polish (1–2 weeks, ongoing)
- **Build:** MkDocs (Diátaxis) docs; README with an asciinema demo; ≥80% coverage; CONTRIBUTING + good-first-issues; PyPI + Docker + Action Marketplace release.
- **Done when:** a stranger installs it and catches the demo API's planted BOLA in under five minutes.

**Placement insight:** Phases 0–3 (~6–9 weeks) already produce a working, defensible, demoable tool with a real confirmed finding. Everything after is upside — build in that order.

---

# 15. Repository structure

Flat and honest; one clear home per concern. No premature abstraction.

```text
wrongdoor/
├── README.md                    # pitch, asciinema demo, 5-min quickstart
├── LICENSE                      # Apache-2.0 (patent grant; corporate-friendly)
├── pyproject.toml               # tiny dep set, entry points, packaging
├── CONTRIBUTING.md · SECURITY.md · CHANGELOG.md
│
├── src/wrongdoor/
│   ├── __init__.py
│   ├── cli.py                   # Typer app: run / lint / report   (the conductor)
│   ├── config/
│   │   ├── schema.py            # Pydantic DSL = the input contract (+ JSON Schema)
│   │   └── loader.py            # safe_load + validate
│   ├── lint/
│   │   └── sanity.py            # bonus static pass: dangling refs, cycles, typos
│   ├── safety/
│   │   └── guard.py             # host allowlist, --confirm, dry-run, rate limits  ← own this
│   ├── identity/
│   │   ├── base.py              # AuthPlugin protocol + AuthedClient
│   │   ├── bearer.py · cookie.py · apikey.py · oauth2.py
│   │   └── manager.py           # authenticate all identities, refresh
│   ├── spec/
│   │   ├── openapi.py           # spec → operation catalog
│   │   └── har.py               # (Phase 5) spec-less import
│   ├── engine/
│   │   ├── seeder.py            # create objects as each identity          ← own this
│   │   ├── ledger.py            # object_id → owner + canonical body       ← own this
│   │   ├── planner.py           # build the test matrix                    ← own this
│   │   ├── executor.py          # async replay across identities           ← own this
│   │   ├── verdict.py           # the oracle: expected vs observed         ← OWN THIS
│   │   └── diff.py              # body normalization + containment match   ← OWN THIS
│   ├── risk.py                  # deterministic severity rubric
│   ├── explain.py               # template explainer (+ optional LLM)
│   └── report/
│       ├── terminal.py · json_report.py · sarif.py · junit.py · html.py
│       └── templates/
│
├── examples/
│   └── vulnerable-api/          # FastAPI multi-tenant demo w/ planted BOLA/BFLA
│       ├── app.py · docker-compose.yml · openapi.json
│       └── config.yaml          # the WrongDoor config that targets it
│
├── tests/
│   ├── unit/                    # verdict engine, body-diff, planner, ledger  (pure logic)
│   ├── integration/             # Testcontainers: run vs demo, assert findings == expected
│   └── security/                # yaml bomb, non-allowlisted target refused, XSS-named field, token-never-logged
│
├── docs/                        # MkDocs (Diátaxis)
├── action/                      # GitHub Action wrapper (action.yml + Dockerfile)
└── .github/workflows/ci.yml     # tests + run WrongDoor vs the demo (dogfood SARIF)
```

The files you must defend line-by-line are `engine/verdict.py`, `engine/diff.py`, `engine/seeder.py`, `engine/ledger.py`, and `safety/guard.py`. Guard that.

---

# 16. Testing strategy

Correctness *is* the product, and your **vulnerable demo API** is the backbone — a live target with a known answer.

- **Integration golden tests (the core):** Testcontainers boots `examples/vulnerable-api`; a test runs the full WrongDoor pipeline against it and asserts the findings equal a checked-in `expected_findings.json` (exact operations, actor/victim, severities). When you add a detector, you add a planted bug + an expected finding. This is how you *know* it works and how you prove it in a viva.
- **False-positive control (non-negotiable for a security tool):** the demo API includes **correctly-secured** endpoints that must yield **zero** findings. Test it explicitly and say you do — false positives destroy a tool's credibility.
- **Verdict-engine unit tests (the trickiest logic, tested in isolation):** feed the oracle *synthetic* `(request, response, ledger)` triples and assert the verdict — non-owner `200` with a body match → VIOLATION; non-owner `403`/`404` → PASS; non-owner `200` **without** body match → INCONCLUSIVE; owner `403` → BROKEN; any `5xx` → INCONCLUSIVE. This nails the four-state logic without any network.
- **Body-diff unit tests:** volatile-field normalization; containment true/false; near-miss bodies (same shape, different values) must **not** match.
- **False-negative tests:** plant BOLAs reachable only *indirectly* (through a create-chain, or on a less-obvious operation) and prove the matrix still catches them.
- **Security tests (double as §13 evidence):** a non-allowlisted target is refused; a YAML bomb is rejected; a response field named `<script>…` is escaped in the HTML report; assert tokens never appear in logs/reports; `--dry-run` sends no requests (assert zero outbound calls).
- **Planner tests:** the matrix excludes self-owned/authorized cells and includes exactly the expected cross-identity combinations.
- **E2E/CI:** the GitHub Action against a workflow-spun demo — assert the build fails and SARIF annotations appear.
- **Coverage:** ≥80%, with `verdict.py`/`diff.py`/`planner.py`/`ledger.py` near-total (pure and small — no excuse).

**How to build the demo so you trust it:** design each vulnerable endpoint *backwards from the finding* — decide "`GET /invoices/{id}` will lack a tenant check," implement exactly that, hand-write the expected finding, then confirm WrongDoor reproduces it. Because you built the bug and the expected answer, you *know* the tool is right when they match — the same determinism the static approach offered, now against a real running app.

---

# 17. Learning path (alongside the build)

Rule: **learn a concept → build the smallest thing that uses it → confirm understanding → move on.** Learn each piece exactly when the project needs it.

```text
async / await + httpx
  ↓ build: fire 100 concurrent GETs with a semaphore; time it vs sequential
  ↓ understand: why the matrix REQUIRES concurrency; how a per-identity client holds a session
HTTP auth flows (bearer/JWT, cookie login, OAuth2, refresh)
  ↓ build: the Identity Manager; authenticate two identities two different ways
  ↓ understand: what a "session per identity" really is; how 401→refresh→retry works
OpenAPI operation/parameter model
  ↓ build: the Spec Importer; list operations + tag object-id params
  ↓ understand: create-ops vs access-ops; path templating
Ground truth by construction (the seeding trick)
  ↓ build: the Seeder + Ledger; create objects as each identity, record ownership
  ↓ understand: why creating the object is what lets you CONFIRM a leak later
The oracle (verdict) + body-diff
  ↓ build: verdict.py + diff.py against synthetic triples FIRST, then live
  ↓ understand: the four states; why a body match is required to claim BOLA
Deterministic risk scoring
  ↓ build: the rubric; score a Critical and a Low by hand, then in code
  ↓ understand: why explainable severity beats a model score in a viva
SARIF / JUnit / CI
  ↓ build: emit SARIF+JUnit; wire the Action; make a bad target turn the check red
  ↓ understand: how authz becomes a build-gating test
```

**What you MUST understand yourself (never outsource):** the seeder/ledger, the verdict engine, the body-diff, the matrix planner, and the safety guard. These *are* the security reasoning and the safety of the tool; they're what you'll be examined on.
**What Claude Code may reasonably help with (after you understand the intent):** Typer/CLI wiring, the Jinja2 HTML template, SARIF/JUnit serialization, the FastAPI demo-app scaffolding, and OpenAPI/HAR parsing plumbing.

---

# 18. Using Claude Code responsibly

Your stated fear — a repo you can't explain — is the exact failure to prevent. Use a fixed workflow and a trust ladder.

**Per-feature workflow:**
```text
Understand the concept  →  Design the interface yourself (names, inputs, outputs, data shapes)
  →  Ask Claude to implement THAT small design  →  Read every line
  →  Ask Claude to explain anything unclear ("why this? what breaks if X?")
  →  Write the tests yourself (or review line-by-line)  →  Break it on purpose (edge case, malformed input, hostile target)
  →  Fix it knowingly  →  Only then move on
```

**Ask Claude to implement:** boilerplate/glue where the design is yours and the security logic isn't — CLI wiring, HTML template, SARIF/JUnit fields, OpenAPI parsing, the demo-app CRUD, test fixtures.

**Implement yourself:** `verdict.py`, `diff.py`, `seeder.py`, `ledger.py`, `planner.py`, `safety/guard.py`. If Claude drafts these, treat the draft as a whiteboard you must be able to reproduce from scratch — because in a viva you will.

**Never accept without full understanding:** anything computing a verdict or a body match (it's the security logic); anything touching secrets, the target URL, request sending, redirects, or HTML output (it's the tool's own attack surface). For these, read every line, ask "what's the malicious/edge input?", and add a `tests/security/` case before accepting.

**Good explanation prompts:** "Explain this verdict branch and give an input that would make it wrong." "Why a containment check instead of equality in the body-diff?" "Walk me through what happens if the target 302-redirects off the allowlist." "What are the security risks in this code and how would you exploit them?" If you can't paraphrase the answer, you don't own it yet.

**Verify implementations:** does it pass *your* tests (not just its own)? Handle the edge case you invented (empty body, `5xx`, owner-denied, non-allowlisted host)? Can you delete its tests, re-derive them, and still pass?

**Avoid dependency creep:** before adding a library, ask "stdlib or something already installed?" Cap direct deps (~7). Every dependency is code you now vouch for in a supply-chain sense — on a security tool that's a talking point, not a footnote.

**Keep a `DECISIONS.md`** (one paragraph per real choice — "containment not equality because responses add server-side fields…"). It forces understanding and is gold in a viva.

---

# 19. What NOT to build (postpone vs. avoid)

| Thing | Verdict | Why |
|---|---|---|
| Microservices | **Avoid** | It's one async process. Splitting it adds network + serialization + failure modes for zero benefit and makes it harder to explain. |
| Kubernetes | **Avoid** (as infra) | You're not operating a fleet. (K8s could host the *demo target*, but even that's overkill vs. Docker Compose.) |
| Message queue / event bus | **Avoid** | Concurrency is handled by asyncio in-process; there's no cross-process work to distribute. |
| A real database, in the MVP | **Postpone** | The ledger is an in-memory dict per run; findings are files. Add SQLite only for run history. |
| Distributed workers | **Postpone** | Only relevant for enormous APIs and runner-sharding — a V3 concern, not now. |
| Full SPA frontend | **Postpone/avoid** | A single-file HTML report + terminal gives the value; a build toolchain teaches you nothing about authz. |
| "AI agent" that decides findings | **Avoid** | Non-deterministic security decisions defeat your explainability goal. The LLM stays a cosmetic explainer. |
| Auto-remediation of the live target | **Avoid** | A tool that *edits* a running app's authz is a foot-gun. Emit the fix for a human; at most patch seeded data via `--cleanup`. |
| Testing production / third-party APIs by default | **Avoid** | Legal + destructive risk. Allowlist + confirmation + own-target-only; authorization in writing before any external target. |
| Mutation/DELETE tests on by default | **Postpone/gate** | Destructive. Reads first; mutations opt-in, test-env only. |
| Supporting every auth type & every spec format at once | **Postpone** | Bearer + cookie login + OpenAPI first, done well. API key/OAuth2/HAR come in Phase 5. |
| Heavy multi-tenant SaaS backend for WrongDoor itself | **Avoid** | Holding clients' credentials and firing at their APIs is a liability, not a portfolio win. |

Through-line: **postpone anything that adds operational surface without adding authorization-testing insight; avoid anything that makes a security decision you can't explain or takes a destructive action you can't undo.**

---

# 20. Final architecture decision (decisive)

**If I were you, I would build WrongDoor as a single-process, async Python CLI that dynamically tests a live API for broken authorization by seeding real objects per identity, recording ground-truth ownership, replaying operations across identities, and confirming leaks by matching responses against the owner's known data — with a single-file HTML report and a GitHub Action as the secondary surfaces, and a small offline "lint my config" pass as a bonus.**

**Stack:**
- **Language:** Python 3.12
- **Backend:** none as a service — a library + CLI (Typer/Rich) that talks only to the target API over async HTTP (httpx + asyncio).
- **Frontend:** a single self-contained HTML report (Jinja2) with the reproducible `curl` pairs; terminal via Rich. No SPA.
- **Database:** none in the MVP (in-memory ownership ledger; findings are files). Optional SQLite for run history, later.
- **Analysis engine:** dynamic, black-box, differential — seeding → ownership ledger → matrix → async replay → deterministic verdict oracle with body-diff confirmation.
- **Authorization model:** identities + auth methods + an access policy (owner-only by default, extendable with role/tenant rules), with true ownership discovered at runtime by construction.
- **Deployment:** `pip install wrongdoor` (PyPI) + a Docker image + a GitHub Action. Runs locally against targets you own; no infrastructure.

**MVP capabilities (what "v1" means):**
1. Authenticate N identities against a live target (bearer + cookie login), safely (allowlist + confirm).
2. Import operations from OpenAPI; seed real objects as each identity and record ground-truth ownership + canonical bodies.
3. Plan and execute the cross-identity test matrix asynchronously against the live target.
4. Confirm **BOLA** (D1) via body-matched verdicts, with a four-state oracle (PASS/VIOLATION/BROKEN/INCONCLUSIVE) that keeps false positives near zero; add BFLA (D2) and unauthenticated-access (D3) on the same machinery.
5. Report to terminal/JSON/SARIF/JUnit/HTML with reproducible `curl` evidence and redaction by default; fail CI above a severity threshold via a GitHub Action.
6. Ship an intentionally-vulnerable FastAPI demo API with planted bugs + expected findings as the known-answer test/demo harness; plus an offline `wrongdoor lint` sanity pass.

**Why this is the right balance:**
- **Cybersecurity depth:** it tests the *real* system for the #1 API risk and confirms findings with ground truth instead of heuristics — a genuinely better oracle than the tools it competes with, and exactly the class of work you did by hand at AdlerQA.
- **Educational value:** you personally build the seeder, ledger, matrix, verdict oracle, body-diff, and safety guard — the concepts you want to master — with nothing important hidden behind a framework.
- **Technical credibility:** async concurrency, real auth flows, a deterministic four-state oracle, SARIF/JUnit/CI integration, and a threat-modeled safety posture. It reads as engineering, not a demo.
- **Portfolio value:** "I automated the authorization testing I did manually at AdlerQA, and it confirms IDOR/BOLA with a reproducible request pair that fails a CI build" is a story recruiters remember — and the red-check demo lands in 90 seconds.
- **Difficulty:** honest medium–high, concentrated in the verdict/seeding logic — impressive but bounded, finishable alone in a final year.
- **Buildable & understandable alone:** one process, one core data structure (the ledger), a tiny dependency set, network I/O only to a target you own — the whole system fits in one head, your non-negotiable constraint.
- **Demoable in a viva:** config → auth → seed → matrix → live replay → body-matched verdict → confirmed finding → `curl` evidence → failing CI check, narratable end to end, against a real running app.
- **Expandable later:** more auth types and spec-less import; dependency chains; mass assignment; test-plan minimization at scale; run history in SQLite; org-wide dashboards — none of which you must commit to now.

**The one-line justification:** WrongDoor proves authorization on the *real running app* by creating the data itself and then trying to steal it back as the wrong user — which is the honest way to test authorization, the direct automation of your internship work, and simple enough (an async client, a dictionary, and a comparison function) that you can build and defend every line.
