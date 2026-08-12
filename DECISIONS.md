# Design decisions

One short paragraph per real choice — the "why", so it can be defended later.

### Dynamic differential testing, not a static model
WrongDoor runs against a live target, creates data as each identity, and tries to
reach it as another. A static "who-should-own-what" YAML only proves the *model*
is self-consistent, not that the *app* is — and model-vs-reality drift is exactly
what causes authorization bugs. So we measure reality.

### Ground truth by construction (the seeder)
Because the seeder *creates* each object as a known identity, ownership is a fact,
not a guess. That is what lets the verdict engine *confirm* a leak instead of
inferring one from response similarity (which is noisy and limited to ~2 identities).

### The ownership ledger keys on (resource_type, object_id)
Real APIs reuse small ids across types (`invoice/1` and `user/1` both exist), so a
bare-id key would cross-wire ownership. object_id is normalized to a string because
JSON returns `1` or `"1"` inconsistently.

### Ledger ownership is write-once; conflicts raise
Recording the same object with a *different* owner can only mean the target handed
two identities the same id (an anomaly) or a seeder bug — either would poison every
verdict — so it raises `LedgerError` rather than silently overwriting ground truth.

### The verdict engine is a pure function with four states
`judge(request, response, ledger)` has no I/O, so it is trivially testable and can't
be an injection vector. It never collapses PASS / VIOLATION / BROKEN / INCONCLUSIVE:
a `500` is inconclusive, an owner denied is BROKEN (a bug, never a security "pass"),
and a `2xx` to a non-owner is only a VIOLATION once the body matches ground truth.

### A 2xx alone is never a leak; a 404 to a non-owner is a PASS
A leaked object returns a perfectly valid `200`, and a filtered/empty `200` looks
identical — so confirmation requires a body match. And because we *know* the object
exists (we made it), a `404` to a non-owner is legitimate deny-by-info-hiding.

### Body-diff uses containment, not equality
A real response carries extra server-added fields, so we require the owner's whole
(non-volatile) object to be *contained* in the response, not equal to it. Full
containment is what discriminates a true leak from a coincidental overlap of a
couple of default fields; a near-miss (same shape, different values) fails.

### BFLA is status-based; BOLA and missing-auth are body-matched
Broken function-level authorization is about reaching an operation at all, so a
non-privileged `2xx` is the finding — there's no object to match. BOLA and
missing-auth are object-level, so they require the body match against ground truth.

### The safety guard fails closed and matches hostnames exactly
Anything ambiguous is a refusal. Host matching is exact equality on the parsed
hostname — never a substring or `endswith`, which is how allowlists get bypassed
(`staging.myapp.test.evil.com`). It raises rather than returning a bool a caller
could forget to check.

### Mutations are off by default; the seeder is sequential and bounded
The flagship BOLA sweep is reads-only unless `--include-mutations` is passed (§13).
Seeding issues writes, so it is sequential (not concurrent like auth) and capped by
`max_objects`, so a bad config can't create a runaway amount of data.

### Secrets live only in the identity layer; reports redact by default
Secrets are referenced by env-var *name* in the config and resolved only in
`identity/`, never logged. Reports emit matched field *names*; response values
appear only behind `--include-bodies`, and the HTML report autoescapes everything.

### API-key auth is header-only, and redaction follows the configured header
The `api_key` auth type sends the key in a header (default `X-API-Key`, but the
header name is configurable because APIs disagree) — never a URL query string, so
a key can't leak into a logged URL (§13). Because the header name is known at
config time, each plugin declares the secret header it sets and that travels with
the `AuthedClient`, so `redacted()` masks the *configured* header, not just a
hardcoded default — redaction stays correct even for a custom header name.

### OAuth2 is an httpx.Auth, and refresh is serialized to avoid a stampede
OAuth2 is the one auth type that must act on every request, not set a header once
— a token can expire mid-run, so we have to see the 401 and re-issue. httpx's own
extension point for that is `httpx.Auth.async_auth_flow` (yield request, inspect
response, yield a retry), so the plugin *is* an `httpx.Auth` rather than bolting
retry logic onto the set-header-once pattern. Because the executor is concurrent,
a just-expired token can 401 many in-flight requests at once; refresh runs under a
lock with a staleness check (`refresh only if the token is still the one that just
failed`) so the first arrival refreshes and the rest reuse the new token instead
of stampeding the token endpoint. When the server issues no refresh token
(common for client-credentials), refresh falls back to re-running the grant.

### Severity is a deterministic, hand-reconstructable rubric
`severity = f(sensitivity, cross_tenant, is_mutation, check)` — a small function of
named factors, so a finding is "Critical because it's a cross-tenant financial GET,"
not "the model scored 0.87." Unauthenticated and BFLA each bump one band.

### Dependency chains: topological create-order + parent-id injection
A child (Project) is seeded only after its parent (Org), and the parent object's id
is injected into the child's create body — and the parent used is one the *same*
identity owns, so ownership chains cleanly. A dependency cycle is a hard error,
caught offline by `wrongdoor lint` (the tool's only graph traversal).

### --cleanup deletes only ledger objects, children first, best-effort
Teardown deletes exactly what the run created — the ledger is the manifest, so
nothing else is ever touched. Deletes go via each resource's spec DELETE op, as
the object's owner (legitimate rights), in the reverse of the seeder's create
order (children before parents, so a parent delete isn't blocked by a live
child). Unlike the seeder (which aborts on a bad write, because forged ground
truth is dangerous), cleanup is best-effort and non-fatal: it treats 404 as
success (already gone == the goal), collects every other failure into a "deleted
N/M; left behind […]" summary, reports resources with no DELETE op instead of
guessing a URL, and never changes the run's exit code — a teardown hiccup must
not mask or fake the security result.

### prance for spec parsing; openapi-core deferred
`$ref` resolution is a solved, subtle problem — we don't reimplement it. openapi-core
(request/response *validation*) isn't needed yet, so it's held until a phase does.

### Banner to stderr
The startup banner is decorative, so it prints to stderr; stdout stays clean for
machine output (`wrongdoor run --format json | jq`).
