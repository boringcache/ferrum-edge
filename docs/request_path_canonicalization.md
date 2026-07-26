# Request Path Canonicalization

Ferrum Edge derives **one canonical policy path** for every HTTP-family
request, at the frontend boundary, before routing or any plugin runs. Routing,
WAF, `openapi_validator`, `request_termination`, authorization, cache and
replay keys, rewrites, `strip_listen_path`, and the request line placed on the
backend connection all read that single value.

Implementation: `src/policy_path.rs`. Boundary call sites:
`src/proxy/mod.rs` (HTTP/1.1 + HTTP/2) and `src/http3/server.rs` (HTTP/3).

## Why one representation

A percent-encoded request target has more than one plausible reading. If the
gateway evaluates policy on the raw target while the backend framework
percent-decodes path segments before dispatch, a client can pick a spelling
that misses an operator's rule and still reaches the protected handler:

| Client sends    | Operator rule | Old gateway reading | Backend dispatches |
| --------------- | ------------- | ------------------- | ------------------ |
| `/%61dmin`      | `/admin`      | `/%61dmin` — no hit | `/admin`           |
| `/api%2Fadmin`  | `/api/admin`  | one segment         | two segments       |

The fix is representational rather than per-plugin: canonicalize once, store
the result in `RequestContext::path`, and let every existing consumer keep
reading that one field. There is no second normalization model and no
per-plugin decoding.

## The contract

`canonicalize_policy_path()` returns either a canonical path or a rejection.

**Fast path.** A target with no `%` is returned unchanged, borrowed, and can
never be rejected. Every behavior change below requires a percent escape.

**Accepted and decoded.** An escape of a character that may appear literally in
a path — RFC 3986 `pchar`, i.e. `unreserved` / `sub-delims` / `:` / `@` — is
decoded to that character. `/%61dmin` becomes `/admin`, `/%40user` becomes
`/@user`.

**No escape survives.** An escape is either decoded to the byte it names or the
request is refused, so a canonical policy path never contains a `%`. That is
what makes the canonical path a single coordinate: the gateway cannot evaluate
one spelling while forwarding another that a decoding backend reads
differently.

**Rejected with `400`.** Each case is a target whose meaning depends on which
component decodes it, so there is no reading the gateway can adopt without
risking disagreement with the backend:

| Reason token             | Example          | Why |
| ------------------------ | ---------------- | --- |
| `invalid_escape`         | `/a%`, `/a%2`, `/a%zz` | A lenient parser and a strict one disagree about where the escape ends. |
| `double_encoding`        | `/a%25b`, `/a%252Fb` | An encoded `%` is the lead byte of any double encoding; a second decode could introduce structure. |
| `encoded_separator`      | `/a%2Fb`, `/a%3Fb`, `/a%23b` | Decoding would add a segment, a query, or a fragment the raw target did not have. |
| `encoded_backslash`      | `/a%5Cb`         | Several backend stacks treat `\` as a path separator. |
| `encoded_control`        | `/a%00`, `/a%0A` | A NUL truncates the path in several runtimes; other C0 controls and `DEL` are equally divergent. |
| `unrepresentable_escape` | `/a%20b`, `/a%7Bb`, `/caf%C3%A9`, `/caf%C3%28` | The escaped byte cannot appear literally in a request target (space, `"`, `<`, `>`, `[`, `]`, `^`, `` ` ``, `{`, `\|`, `}`, and every non-ASCII byte, valid UTF-8 sequence or not). Keeping it escaped would put a different string on the wire than the one policy read; decoding it would produce an untransmittable target. Neither is a single coordinate, so the target is refused. |
| `ambiguous_dot_segment`  | `/a/%2e%2e/b`    | A percent escape produced a `.` or `..` segment. |

Rejections carry a fixed JSON body and a fixed reason token. Neither echoes any
request bytes, and the reject is logged with the reason token only.

**Literal dot segments are not rejected.** `/a/../b` passes through exactly as
written. Canonicalization refuses ambiguity; it never rewrites a request's
meaning, and a literal `..` is equally visible to the operator, the gateway,
and the backend.

## Invariants this buys

1. **Structure preservation.** Because every escape that could decode to a
   separator is rejected, the canonical path has exactly the segment structure
   of the raw target. Routing, `openapi_validator` parameter segments (`[^/]+`),
   and the backend cannot disagree about how many segments a request has.
2. **Decode idempotence.** `canonicalize(canonicalize(p)) == canonicalize(p)`,
   and a further decode of a canonical path is a no-op — there is no escape
   left to decode.
3. **One coordinate system.** Only `pchar`-legal bytes are decoded and no
   escape survives, so the canonical path is itself a valid HTTP request target
   *and* is byte-identical to what a decoding backend resolves. Policy
   evaluation and backend forwarding use the same string; `strip_listen_path`
   offsets measured by the router are valid offsets into the forwarded path.
   There is no spelling left on which a policy rule and the application can
   disagree.

## Protocol parity

HTTP/1.1, HTTP/2, and HTTP/3 run the check at the same point in the request
ordering — after transport-level validation (URL length, query-parameter count,
`check_protocol_headers`, `check_host_authority_consistency`) and before
routing, every plugin phase, and backend dispatch. All three accept and reject
the same set of targets. HTTP/3 shapes the rejection for gRPC / gRPC-Web the
same way its other `400` rejections are shaped.

## Configured paths must be canonical too

Operator-authored path values are compared against the canonical request path,
so a non-canonical configured value can never match. Because no escape survives
canonicalization, a configured path is canonical exactly when it contains no
percent escape. Rather than silently never firing, non-canonical values are
rejected at admission using the same canonicalizer:

- `Proxy.listen_path` — rejected by `Proxy::validate_fields()` and by the
  dedicated `GatewayConfig::validate_listen_path_encodings()` that runs on
  every load and reload path, including SQL/DP loads where the catch-all
  validator is warn-only.
- `request_termination` `trigger.path_prefix` — rejected by the plugin
  constructor, and therefore by Admin API validation, file-mode startup, and DB
  admission.

WAF `conditions.paths`, `openapi_validator` path regexes, and other
regex-shaped path scopes are operator-authored patterns rather than literal
paths and are not canonicalized; write them against the canonical form.

## Raw target

The client's original target is retained on the request context only when
canonicalization changed it, and is readable through
`RequestContext::raw_path()`. Its single sanctioned consumer is `hmac_auth`,
whose signing string binds the literal bytes the client signed and so cannot
verify against a rewritten spelling. Nothing else may consume it: routing and
every policy surface run on the canonical path, so a raw spelling can never
select a different route, operation, or rule than the backend executes.

Transaction logs record the canonical path.

## Operational impact

This is a behavior change for three shapes of traffic that previously succeeded:

- Targets with encoded separators (`%2F`, `%252F`) were folded into `/` for
  route lookup and now receive `400`. Folding changes segment structure, so a
  folded route decision could still disagree with a backend that does not
  decode; refusing cannot. APIs that carry an encoded `/` inside a path
  parameter must move that value into the query string or a header.
- Targets with a percent escape that decoded to a `.` or `..` segment now
  receive `400`.
- Targets carrying an escape of a character that cannot be written literally in
  a path — `%20` for space, `%7B`/`%5B` for brackets, and any percent-encoded
  non-ASCII text such as `/caf%C3%A9` — now receive `400`
  (`unrepresentable_escape`). This is the broadest of the three: **percent-encoded
  spaces and non-ASCII path segments are no longer accepted at all.** The
  gateway has no way to hold one such target that both policy and a decoding
  backend read the same way, so it refuses rather than authorize a spelling the
  application may resolve differently. APIs that need spaces or non-ASCII text
  in a resource identifier must carry that value in the query string, a header,
  or a body field, or use a `pchar`-legal identifier in the path.

There is no configuration switch for any of them. A per-deployment opt-out would
mean policy is computed differently depending on config, which is the class of
divergence this representation exists to eliminate.

## Related

- `docs/routing.md` — route matching and `strip_listen_path`
- `docs/plugins.md` — `waf`, `openapi_validator`, `request_termination`,
  `hmac_auth`
- `src/router_cache.rs` `normalize_encoded_slashes()` — the predecessor helper,
  retained only as an unreachable defense-in-depth residual for callers that do
  not enter through the frontend boundary
