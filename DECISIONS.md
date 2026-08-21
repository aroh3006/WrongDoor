# Design decisions

One short paragraph for each real decision made in this project. Each one explains the why. That way it's easy to defend later.

### Dynamic differential testing, not a static model
WrongDoor runs against a live target. It creates data as each identity. Then it tries to reach that data as another identity.

A static "who-should-own-what" YAML file only proves the *model* is self-consistent. It doesn't prove the *app* is. The gap between the model and the real app is exactly what causes authorization bugs. So instead of trusting a model, we measure the real thing.

### Ground truth by construction (the seeder)
The seeder creates each object as a known identity. That makes ownership a fact, not a guess. This is what lets the verdict engine *confirm* a leak instead of inferring one from how similar two responses look. Inferring from similarity is noisy. It also only works well with about two identities.

### The ownership ledger keys on (resource_type, object_id)
Real APIs reuse small ids across types. `invoice/1` and `user/1` can both exist at the same time. A bare id key would cross-wire ownership between them, so the key is `(resource_type, object_id)` instead. object_id always gets normalized to a string. JSON returns `1` or `"1"` inconsistently for the same id, and that would otherwise cause mismatches.

### Ledger ownership is write-once; conflicts raise
If the same object gets recorded with a *different* owner, something is wrong. Either the target handed two identities the same id (an anomaly), or there's a bug in the seeder. Either way, every verdict after that point would be poisoned. So instead of silently overwriting ground truth, this raises `LedgerError`.

### The verdict engine is a pure function with four states
`judge(request, response, ledger)` does no I/O. That makes it trivially testable. It also means it can't become an injection vector.

It never collapses the four states into fewer. A `500` is always INCONCLUSIVE. An owner getting denied is always BROKEN (a bug, never a security "pass"). A `2xx` to a non-owner only counts as a VIOLATION once the body actually matches ground truth.

### A 2xx alone is never a leak; a 404 to a non-owner is a PASS
A leaked object returns a perfectly valid `200`. A filtered or empty `200` looks exactly the same from the outside. So confirming a leak requires actually matching the body, not just checking the status code.

We *know* the object exists, since we created it ourselves. So a `404` to a non-owner isn't suspicious. It's a legitimate way of denying access without revealing that the object exists.

### Body-diff uses containment, not equality
A real response usually carries extra fields the server adds on its own. So instead of requiring the response to *equal* the owner's object, we require it to *contain* the owner's whole non-volatile object. Full containment is what tells a true leak apart from a coincidental overlap of a couple of default fields. A near-miss (same shape, different values) still fails.

### BFLA is status-based; BOLA and missing-auth are body-matched
Broken function-level authorization is about reaching an operation at all. There's no object to match. A non-privileged `2xx` response is itself the finding.

BOLA and missing-auth work differently. They are object-level checks, so they need the body to actually match against ground truth.

### The safety guard fails closed and matches hostnames exactly
Anything ambiguous gets refused. Host matching uses exact equality on the parsed hostname. It's never a substring check or `endswith`, because that's exactly how allowlists get bypassed (for example, `staging.myapp.test.evil.com`). The guard also raises an error instead of returning a true/false value. A caller could too easily forget to check a returned bool.

### Mutations are off by default; the seeder is sequential and bounded
The main BOLA sweep only reads data, unless `--include-mutations` is passed (§13). Seeding does issue writes though. Because of that, seeding runs sequentially instead of concurrently, unlike auth, which runs concurrently. Seeding is also capped by `max_objects`. That way a bad config can't accidentally create a huge amount of data.

### Secrets live only in the identity layer; reports redact by default
The config only ever references secrets by env-var *name*. The actual value gets resolved only inside `identity/`. It's never logged.

Reports only emit the *names* of matched fields, not the values. Actual response values only show up if you pass `--include-bodies`. The HTML report also autoescapes everything it renders.

### API-key auth is header-only (redaction follows the configured header)
The `api_key` auth type always sends the key in a header. The default header is `X-API-Key`, but the header name can be configured, since different APIs use different conventions. The key never goes into a URL query string. That way it can't leak into a logged URL (§13).

The header name is known at config time, so each auth plugin declares which header it puts the secret in. That information travels along with the `AuthedClient`. So `redacted()` can mask the actual *configured* header, not just a hardcoded default. Redaction stays correct even with a custom header name.

### OAuth2 is an httpx.Auth (refresh is serialized to avoid a stampede)
OAuth2 is the one auth type that has to act on every single request, instead of just setting a header once. A token can expire in the middle of a run. When that happens, we need to see the 401 and re-issue the request with a fresh token.

httpx has a built-in extension point for exactly this: `httpx.Auth.async_auth_flow`. It yields a request, inspects the response, and can yield a retry. So instead of bolting retry logic onto the normal set-header-once pattern, the OAuth2 plugin *is* an `httpx.Auth`.

The executor runs requests concurrently. That means a token expiring can cause many in-flight requests to 401 at almost the same time. To handle that, refresh runs under a lock with a staleness check: only refresh if the token is still the one that just failed. The first request to hit this refreshes the token. The rest just reuse the new one, instead of all hammering the token endpoint at once.

If the server doesn't issue a refresh token (this is common with client-credentials), the refresh step just re-runs the original grant instead.

### Config errors are rendered from field locations, never the input value
`extra="forbid"` correctly rejects an inline secret. But pydantic's default error message embeds `input_value=...`, which would print out the exact secret it just caught. That's a problem. So the loader builds its own error message using only each error's `loc` (the field path) and `msg`. It never uses `input`. This way the error can name the offending field without ever echoing its value.

### Credential-POST endpoints are allowlist-checked, not just base_url
The host allowlist already gated `base_url` and every write. But a `login` url or an `oauth2` `token_url` is where credentials actually get POSTed. An absolute, off-allowlist URL there would let credentials slip past the base_url check entirely.

To close that gap, each auth plugin now declares its own `auth_urls`. The manager checks these against the allowlist (resolved against base_url) before authenticating.

### Severity is a deterministic, hand-reconstructable rubric
`severity = f(sensitivity, cross_tenant, is_mutation, check)`. It's a small function of named factors. This means a finding can say "Critical, because it's a cross-tenant financial GET," instead of something meaningless like "the model scored 0.87." Unauthenticated access and BFLA findings each bump the severity up by one band.

### Dependency chains: topological create-order + parent-id injection
A child resource, like Project, only gets seeded after its parent, like Org. The parent's id then gets injected into the child's create body. The parent used is always one the *same* identity owns. That's what makes ownership chain cleanly through the hierarchy.

A dependency cycle is treated as a hard error. It's caught offline by `wrongdoor lint`, which is the tool's only graph traversal.

### --cleanup deletes only ledger objects, children first, best-effort
Teardown deletes exactly what the run created, nothing more. The ledger acts as the manifest. Because of that, nothing else on the target ever gets touched.

Deletes go through each resource's spec DELETE operation. They run as the object's owner, since the owner has legitimate delete rights. They also run in the reverse of the seeder's create order: children before parents. That way a parent delete never gets blocked by a still-live child.

The seeder aborts on a bad write, since forged ground truth is dangerous. Cleanup works the opposite way: it's best-effort and non-fatal. A 404 counts as success, since the object already being gone is the actual goal. Every other kind of failure gets collected into a summary, something like `"deleted N/M; left behind [...]"`. If a resource has no DELETE operation, cleanup reports that instead of guessing at a URL. Cleanup also never changes the run's exit code. A teardown hiccup should never mask or fake the real security result.

### HAR import reuses the OpenAPI catalog and never touches auth
A HAR capture is basically a second front-end. It produces the exact same `Operation` list the OpenAPI importer produces. It reuses that importer's `Operation` and `Parameter` types, along with its `_classify` and `_resource_type` helpers. Because of that, the planner, seeder, executor, and verdict engine all stay importer-agnostic. A `.har` file and an OpenAPI spec are interchangeable at `--spec`. The tool just dispatches based on the file extension.

There's one piece of information a HAR doesn't give us directly: whether `/invoices/1000` and `/invoices/1001` are really the same templated operation. We figure this out by shape. A segment made of digits, a UUID, or a long hex string becomes `{param}`. The result then gets handed to the same `_classify` function used for specs.

Recorded create bodies become `request_schema={"example": body}`. `synthesize_body` already knows how to replay that format, so the seeder doesn't need any changes.

Auth is deliberately never extracted from a HAR file. Recorded credentials are secrets. They're also usually stale by the time you'd use them anyway. More importantly, a HAR only ever captures ONE identity, and the differential method needs at least two. So auth always stays config-based. Any recorded Authorization or Cookie headers just get ignored.

### Mass-assignment (D4) is update-based and reuses the ledger as a before/after baseline
Mass-assignment (OWASP API3) asks a different question than BOLA. Instead of "can a non-owner READ my object", it asks "can the owner SET a field they shouldn't control?" It reuses the same "ground truth by construction" trick BOLA uses, just pointed at a different question.

The seeder already captures each object's canonical body before any attack happens. That gives us a free ground-truth baseline. The prober PATCHes or PUTs the object as its own owner. The owner already has legitimate rights to update the object, so the only real question is whether the request body can set a field it shouldn't be able to. The prober injects one declared value chosen to be different from the baseline. Then it re-reads the object and checks the persisted state. A 2xx response on the update proves nothing by itself, since the field could have been silently stripped by the server.

This keeps confirmation at the same bar as BOLA: a before/after difference on an object with known ground truth. The only thing that's config, rather than inferred, is *which* fields are off-limits. That lives in `resources.<type>.protected_fields`, a map from field name to an illegitimate value. Which fields are protected is policy, and the tool has no way to infer that on its own.

The value itself gets carried along, not just the field name. That keeps the injected value type-correct, which means a rejection is a real authorization refusal, not just a validation error.

This first version is update-based, since it needs a PUT or PATCH operation. It's the first cut because it doesn't create any new objects and gets its baseline for free. Create-based mass-assignment is left for later.

Because this detector writes data, it only runs under `--include-mutations`. It also only runs for resources that declare `protected_fields`. That's a double opt-in. It also always runs after the BOLA matrix has already been judged. That way its mutations can't affect those earlier verdicts.

### D4 adds sibling functions rather than bending judge() / confirm_leak()
The mass-assignment decision lives in a new, pure `judge_injection` function, sitting beside `judge`. The body check lives in a new `confirm_injection` function, sitting beside `confirm_leak`. Neither existing function got new branches added to it.

`judge` only takes `(request, observed, ledger)`. It has no way to see the second observation D4 needs, which is the re-read, or the injected value. `confirm_leak` also proves a different kind of claim: a *whole-object* containment claim. Mass-assignment needs a *field-level* claim instead, something like "this one field took my value. It changed from the baseline."

Keeping the main BOLA path untouched keeps its regression risk at zero. The new pure functions are just as testable as the old ones. `confirm_injection` still follows diff.py's existing rules. It only works with dicts. It uses equality checks. It uses the `_MISSING` sentinel like the rest of the file does. It also reuses `normalize` to strip volatile fields off the body before resubmitting it.

Severity gets one extra `massassign` bump on top of the existing mutation bump. Escalating yourself using a server-controlled field is high-impact. So a high-sensitivity resource ends up landing at Critical.

### prance for spec parsing; openapi-core deferred
`$ref` resolution is a solved but subtle problem. We don't try to reimplement it ourselves.

openapi-core would handle request and response *validation*. We don't need that yet. It's held off until a later phase actually needs it.

### The CLI prints nothing decorative on startup
Running a command goes straight to doing the work. There's no startup banner or splash output. Anything that isn't a result is noise for someone piping output into another tool. Operational notes still go to stderr. That keeps stdout clean for machine-readable output, like `wrongdoor run --format json | jq`.
