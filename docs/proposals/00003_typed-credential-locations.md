# Plan: Typed Credential Locations for JWT Identity Plugin (Issue #64)

## Context

The JWT identity plugin (`builtins/plugins/identity-jwt/`) currently only extracts JWTs from HTTP headers. Issue #64 requests support for cookies and query parameters — one location per resolver instance — while keeping the existing `header: "Authorization"` config backward-compatible.

## Config Format Examples

### Today (header only, unchanged)

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      header: "Authorization"
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

### New: JWT from a cookie (e.g. browser app with HttpOnly cookie)

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      credential_location:
        kind: cookie
        name: __Host-jwt
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

### New: JWT from a query parameter (e.g. WebSocket/SSE that can't set headers)

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      credential_location:
        kind: query_param
        name: access_token
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

### New: header in the typed form (equivalent to the old form)

```yaml
config:
  credential_location:
    kind: header
    name: Authorization
  trusted_issuers: [...]
```

### Invalid: both old and new form together

```yaml
config:
  header: "Authorization"
  credential_location:
    kind: cookie
    name: __Host-jwt
# → config error: "header and credential_location are mutually exclusive"
```

### Two resolvers: user JWT from header + workload SVID from header

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      role: user
      header: "Authorization"
      trusted_issuers: [...]

  - name: workload-jwt
    kind: identity/jwt
    config:
      role: workload
      header: "X-Workload-Token"
      trusted_issuers: [...]
```

---

## Phase 1: Core Types (`ppe-core`)

### 1a. `CredentialLocation` enum

Add to `crates/ppe-core/src/extensions/raw_credentials.rs`:

```rust
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialLocation {
    Header { name: String },
    Cookie { name: String },
    QueryParam { name: String },
}
```

Follows the `#[serde(tag = "kind")]` pattern used by `DecodingKeySource`. Add a `Display` impl for error messages (e.g. `header 'Authorization'`, `cookie 'session_token'`). Re-export from `extensions/mod.rs`.

**Why `ppe-core`, not the JWT plugin:** `CredentialLocation` describes *where* a credential was extracted from — a concern shared by every identity plugin, not just the JWT one. Placing it in `ppe-core` means the JWT plugin, a future X.509/mTLS plugin, a future WIMSE Proof Token plugin, or any custom identity resolver all record credential origin using the same type on `RawInboundToken.source`. Downstream consumers (audit logging, assertion propagation, policy predicates, the delegation layer) see a uniform `CredentialLocation` and can answer "where did this credential come from?" without plugin-specific logic. If the type lived inside the JWT plugin, each future plugin would need its own location type and every consumer would need to know about all of them.

### 1b. Evolve `RawInboundToken`

Add `source: Option<CredentialLocation>` field alongside the existing `source_header: String` (kept for backward compat). Update `RawInboundToken::new()` to auto-populate `source` as `Header { name }`. Add `RawInboundToken::with_location(token, location, kind)` for new callers.

**Rationale for keeping `source_header`**: It's `pub`, used by forwarding plugins and ~30 test assertions. Removing it is a breaking change; adding `source` alongside is additive.

## Phase 2: Data Surface on `IdentityPayload`

### 2a. New fields on `IdentityPayload`

In `crates/ppe-core/src/identity/payload.rs`, add:

```rust
#[serde(default, skip_serializing_if = "HashMap::is_empty")]
cookies: HashMap<String, String>,

#[serde(default, skip_serializing_if = "HashMap::is_empty")]
query_params: HashMap<String, String>,
```

With builder methods `.with_cookies(h)` / `.with_query_params(h)` and getters `cookies()` / `query_params()`.

**Why on `IdentityPayload` not `HttpExtension`**: Consistent with how `headers` already lives on the payload. The issue explicitly requires query params to come from the host, not parsed from `HttpExtension.path` (which strips query strings). The resolver's primary input is `&IdentityPayload`, not `&Extensions`.

### 2b. Cookie fallback

When `payload.cookies()` is empty, the resolver falls back to parsing the `Cookie` header from `payload.headers()` — day-one compatibility for hosts not yet populating the new field. Hand-rolled parser (split on `; `, split on first `=`, trim). Duplicate cookie names → deny with `auth.ambiguous_credential`.

### 2c. Query parameter: no fallback

If `payload.query_params()` is empty and the resolver is configured for query extraction, it denies. The issue says "explicit request target from host" — deliberately no `HttpExtension.path` parsing.

## Phase 3: Plugin Config (backward-compatible)

### 3a. Config struct changes

In `builtins/plugins/identity-jwt/src/config.rs`, keep `deny_unknown_fields` and change `header: String` to `header: Option<String>`, add:

```rust
#[serde(default)]
pub header: Option<String>,

#[serde(default)]
pub credential_location: Option<CredentialLocation>,
```

### 3b. Constructor resolution

In `JwtIdentityResolver::new()`:
- Both `None` → default `Header { name: "Authorization" }`
- `header: Some(name)` only → `Header { name }`
- `credential_location: Some(loc)` only → use it
- Both `Some` → config error

### 3c. Validation

- `Header { name }`: non-blank
- `Cookie { name }`: non-blank, no `=` or `;`
- `QueryParam { name }`: non-blank

## Phase 4: Extraction Logic

### 4a. Extract `extract_token()` helper

In `resolver.rs`, factor lines 670-697 (the header lookup, `Bearer` strip, `raw_token` fallback, and empty check inside `handle()`) into `fn extract_token(&self, payload: &IdentityPayload) -> Result<String, PluginViolation>` that branches on `self.location`:

- **Header**: existing logic (lowercase lookup, `Bearer ` strip, `raw_token` fallback). Error code: `auth.malformed_header` (unchanged).
- **Cookie**: look up in `payload.cookies()`, fallback parse `Cookie` header, reject duplicates. Error codes: `auth.missing_credential`, `auth.empty_credential`, `auth.ambiguous_credential`.
- **QueryParam**: look up in `payload.query_params()`, no fallback. Same error codes as cookie.

### 4b. Update `RawInboundToken` construction

Change line 896 from `RawInboundToken::new(raw_token, self.header.clone(), kind)` to use `RawInboundToken::with_location(raw_token, self.location.clone(), kind)`.

## Phase 5: Tests

### Unit tests
- `CredentialLocation` serde round-trips (in `raw_credentials.rs`)
- Config deserialization: `header:` alone, `credential_location:` alone, both → error, neither → default, blank name → error, misspelled key → rejected

### Extraction tests (resolver.rs `#[cfg(test)]`)
- Cookie: found, missing, empty, fallback from `Cookie` header, duplicate name → ambiguous
- Query param: found, missing, empty, host didn't supply params → deny

### E2E tests (tests/jwt_e2e.rs)
- `valid_jwt_from_cookie_resolves_subject`
- `valid_jwt_from_query_param_resolves_subject`
- `raw_inbound_token_records_cookie_origin`
- `raw_inbound_token_records_query_param_origin`

### Test helper changes (tests/common/mod.rs)

The existing `invoke()` helper (line 135) creates `IdentityPayload::new(token, source)` with no way to pass cookies or query params. Add an `invoke_with_payload()` variant that takes a pre-built `IdentityPayload`, so cookie and query-param tests can populate the new fields via `.with_cookies()` / `.with_query_params()` before driving through the pipeline. The existing `invoke()` stays as-is for backward compat — all current e2e tests use it unchanged.

```rust
pub(crate) async fn invoke_with_payload(
    cfg: PluginConfig,
    payload: IdentityPayload,
) -> PipelineResult {
    let resolver = JwtIdentityResolver::new(cfg.clone())
        .expect("the resolver must construct");

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::new(resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .expect("registration");
    mgr.initialize().await.expect("initialize");

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
}
```

Cookie and query-param e2e tests build their payload explicitly:

```rust
let mut cookies = HashMap::new();
cookies.insert("__Host-jwt".to_owned(), token.clone());
let payload = IdentityPayload::new("", TokenSource::Bearer)
    .with_cookies(cookies);
let result = invoke_with_payload(cfg, payload).await;
```

### Backward compat
All existing tests must pass unmodified — `header:` configs, `source_header` assertions, `IdentityPayload::new()` without cookies/query_params all default to empty. The existing `invoke()` helper is unchanged.

## Dependencies

No new crate dependencies required. Cookie header parsing is hand-rolled (RFC 6265 format is trivial). Query params come pre-parsed from the host.

## Files to Modify

| File | Change |
|------|--------|
| `crates/ppe-core/src/extensions/raw_credentials.rs` | `CredentialLocation` enum, `RawInboundToken` new field + constructor |
| `crates/ppe-core/src/extensions/mod.rs` | Re-export `CredentialLocation` |
| `crates/ppe-core/src/identity/payload.rs` | `cookies`, `query_params` fields + builders + getters |
| `builtins/plugins/identity-jwt/src/config.rs` | `header: Option<String>`, new `credential_location` field, remove `default_header()` |
| `builtins/plugins/identity-jwt/src/resolver.rs` | `extract_token()` helper, constructor validation, `RawInboundToken` construction, new tests |
| `builtins/plugins/identity-jwt/tests/jwt_e2e.rs` | E2E tests for cookie and query-param paths |
| `builtins/plugins/identity-jwt/tests/common/mod.rs` | Helper variants for cookie/query payloads |

## Verification

```console
make check          # type-check both feature sets
make test           # all workspace tests (two passes)
make lint           # fmt + clippy
cargo test -p praxis-policy-plugin-identity-jwt --lib   # plugin unit tests
cargo test -p praxis-policy-plugin-identity-jwt         # plugin + e2e tests
cargo test -p praxis-policy-core --lib                  # core type tests
```

## AIMS Gap Analysis: Token Delivery Mechanisms

The IETF AI Agent Authentication draft ([draft-klrc-aiagent-auth-00](https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-00.html)) Section 9 defines how agents present credentials on the wire. This section evaluates whether the three credential locations in this PR (header, cookie, query parameter) are sufficient, or whether AIMS suggests additional delivery mechanisms the `identity-jwt` plugin should support.

### Conclusion: No additional locations needed for `identity-jwt`

Header, cookie, and query parameter cover every HTTP transport where a bearer JWT arrives. AIMS does not suggest a fourth. The mapping by caller type:

| Caller type (per AIMS) | Authentication flow | Where the JWT arrives | Covered? |
|---|---|---|---|
| Human user via browser | OAuth authorization code → session cookie | Cookie (`__Host-jwt`) | Yes — this PR adds it |
| Human user via API client | OAuth authorization code → access token | `Authorization: Bearer` header | Yes — existing |
| Agent / service (autonomous) | Client credentials or JWT-SVID | `Authorization: Bearer` or custom header | Yes — existing |
| Agent via WebSocket/SSE | Can't set headers on upgrade handshake | Query parameter (`?access_token=`) | Yes — this PR adds it |
| Agent via mTLS | X.509 certificate in TLS handshake | `X-Forwarded-Client-Cert` header (not a JWT) | Out of scope — different credential format |
| Agent via WPT | WIMSE Proof Token bound to a WIT | `Workload-Proof-Token` header (not a standalone JWT) | Out of scope — different validation model |
| Agent via HTTP Message Signatures | RFC 9421 signature over the request | `Signature` / `Signature-Input` headers (not a token) | Out of scope — not a token at all |

### Why the last three don't belong in `identity-jwt`

The draft's Section 9 defines three authentication mechanisms beyond bearer JWTs. None are "JWTs arriving at a different location" — they are fundamentally different credential formats with different validation logic:

**mTLS / X.509-SVID (§9.1):** The credential is an X.509 certificate chain, not a JWT. Validation means ASN.1 parsing, CA trust bundle verification, and SPIFFE ID extraction from SAN URI extensions. None of the JWT plugin's code (JWKS fetching, `exp`/`nbf`/`aud` claim validation, claim mapping) applies.

**WIMSE Proof Tokens (§9.2.1):** A WPT *is* a JWT, but it cannot be validated with the JWT plugin's pipeline. A WPT proves possession of the private key matching a companion WIT's public key — not an IdP's JWKS endpoint. The plugin would need to verify the `wth` claim (hash binding to the WIT), enforce `jti` replay detection, and validate against the WIT's key rather than a configured issuer. Bolting this onto `identity-jwt` would mean special-casing every step of the validation pipeline.

**HTTP Message Signatures (§9.2.2):** Not a token at all. Verification means parsing RFC 9421 structured fields (`Signature`, `Signature-Input`), reconstructing the signature base from HTTP message components (method, request-target, content-digest), and verifying against a WIT's public key. There is no JWT decode step.

Each of these belongs in its own identity plugin (see Future Work below), not as additional `CredentialLocation` variants.

### What about RFC 6750 §2.2 (form-encoded body)?

RFC 6750 defines a third bearer token delivery method: `access_token` as a form-encoded POST body field. This is deprecated by OAuth 2.0 Security BCP (RFC 9700) and only works for `application/x-www-form-urlencoded` POST requests. Not worth supporting.

### How `CredentialLocation` in `ppe-core` helps close the AIMS gaps

By placing `CredentialLocation` in `ppe-core` rather than in the JWT plugin, future plugins for the three AIMS mechanisms above can record their credential origin using the same type:

- An `identity/x509` plugin records `CredentialLocation::Header { name: "X-Forwarded-Client-Cert" }`
- An `identity/wpt` plugin records `CredentialLocation::Header { name: "Workload-Proof-Token" }`
- An `identity/httpsig` plugin records `CredentialLocation::Header { name: "Signature" }`

Downstream consumers (audit, assertions, policy) see a uniform `CredentialLocation` regardless of which plugin produced it.

## Future Work: AIMS-Motivated Identity Plugins

The IETF AI Agent Authentication draft (draft-klrc-aiagent-auth-00) defines authentication mechanisms beyond bearer JWTs. The `CredentialLocation` enum introduced in this PR is designed to be reused by these future plugins — each would record its credential origin on `RawInboundToken.source` using the same type.

### `identity/x509` — mTLS / X.509-SVID (AIMS §9.1)

The draft's transport-layer authentication path. PPE already has `TokenSource::Mtls` and the `WorkloadIdentity` slot on `SecurityExtension`, but no builtin plugin processes X.509 certificate chains. A plugin would:

- Parse the `X-Forwarded-Client-Cert` header (Envoy/Istio XFCC format) or `X-Client-Cert` (RFC 9440)
- Decode the X.509 leaf certificate and chain
- Extract the SPIFFE ID from the SAN URI (`spiffe://<trust-domain>/<path>`)
- Validate the chain against a configured trust bundle (CA certs per trust domain)
- Check `notBefore` / `notAfter` expiry
- Populate `caller_workload` with `spiffe_id`, `trust_domain`, `attestor: "mtls"`, `attested_at`
- Record `CredentialLocation::Header { name: "X-Forwarded-Client-Cert" }` on the `RawInboundToken`

This is the most immediately relevant gap — it maps to deployed infrastructure (Istio, SPIRE, Envoy) that PPE's target audience already runs. Would compose naturally with the JWT plugin via the multi-resolver chain (`authentication: [user-jwt, x509-attestor]`): JWT resolves the user, X.509 resolves the workload, both land on the same `IdentityPayload`.

### `identity/wpt` — WIMSE Proof Tokens (AIMS §9.2.1)

The draft's primary application-layer proof-of-possession mechanism for workload authentication across proxies. A plugin would:

- Extract the `Workload-Proof-Token` header
- Verify the WPT JWT signature against the companion WIT's public key
- Validate the `wth` claim (hash of the WIT) binds the proof to the identity
- Check `aud`, `exp`, `jti` (with replay detection via `jti` uniqueness)
- Populate `caller_workload`
- Record `CredentialLocation::Header { name: "Workload-Proof-Token" }`

Lower priority — the WIMSE drafts are early (-00). The `jti` replay detection this would require is also a gap in the current JWT plugin (AIMS §9.2.3 MUST-level requirement).

### `identity/httpsig` — HTTP Message Signatures (AIMS §9.2.2)

The draft's strongest authentication mechanism, providing message integrity and identity via RFC 9421 signatures. A plugin would:

- Parse `Signature` and `Signature-Input` structured headers
- Verify the signature against the WIT's public key
- Validate mandatory signed components: method, request-target, content-digest, WIT
- Populate `caller_workload`

Lowest priority — most complex to implement and also depends on early WIMSE drafts. Would additionally require response signing support on the assertions layer for full coverage.
