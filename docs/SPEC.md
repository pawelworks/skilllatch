# SkillLatch Formats and Decision Semantics (SPEC)

**Status:** Draft. Matches the 0.1.x reference implementation in this
repository. Audience: implementers of verifiers, ports, and host adapters.

**Standing rule:** where this document and the reference parser in
[skilllatch/core.py](../skilllatch/core.py) disagree, the parser is
authoritative until the discrepancy is fixed. Report discrepancies as bugs.

## 1. Scope

This document specifies:

- canonical JSON and digest computation (§3);
- the capability manifest, version 1 (§5);
- the session/task grant, versions 1 and 2 (§6);
- action requests (§7);
- the decision receipt, version 2, with version 1 as historical (§8);
- the reason-code registry (§9);
- the evaluation pipeline order (§10);
- versioning and extensibility rules (§11);
- determinism guarantees (§12);
- receipt verification and the audit log format `skilllatch.audit.v1` (§13);
- deterministic resource limits (§14).

Out of scope: the scanner report mapping (`load_scan_report` and its
`skilllatch.scan_advisory.v1` summary are an advisory loader, not a wire
format), host dispatch and tool invocation, TLS, and process isolation. See
[THREAT_MODEL.md](THREAT_MODEL.md) for those boundaries.

## 2. Terminology

- **host** — the trusted component that owns the skill snapshot, policy
  inputs, clock, request metadata, and the actual tool invocation.
- **skill tree** — the directory of skill files the host approved.
- **manifest** — the skill's declared capability ceiling (files, HTTPS
  origins, exact command argument vectors).
- **grant** — a short-lived user/host authorization for one task and
  session; may narrow, never widen, the manifest; version 2 may pin one
  workspace identity.
- **request** — one proposed tool action, normalized to one of three kinds.
- **decision** — the allow/deny outcome of the evaluation pipeline.
- **receipt** — the JSON record binding the decision to the canonical
  inputs and the evaluation time.
- **audit log** — a JSONL hash chain of receipts (`skilllatch.audit.v1`).
- **canonical JSON** — the single byte serialization defined in §3.
- **digest** — `"sha256:"` + lowercase hex SHA-256 of canonical JSON bytes.

## 3. Canonical JSON and digests

### 3.1 Definition

Canonical JSON is `json.dumps(value, sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)` encoded as UTF-8. The digest of a
value is `"sha256:"` followed by the lowercase hex SHA-256 of its canonical
bytes (`skilllatch.core._sha256`).

### 3.2 Value domain and rejections

Canonicalization accepts exactly: `null`, booleans, integers (arbitrary
precision), finite floats, strings, arrays, and objects with string keys.
Validation is iterative and does not depend on document recursion. The
following are rejected:

- non-JSON Python values (sets, bytes, tuples-as-tuples are fine only as
  lists, custom objects, …) → `invalid_json_value`;
- non-string object keys → `invalid_json_value`;
- nonfinite floats (`inf`, `-inf`, `nan`) → `invalid_json_value`;
- nesting deeper than 100 levels (root = 1) → `limit_exceeded`.

### 3.3 Cross-language serialization quirks a verifier MUST reproduce

Canonical bytes are CPython's `json.dumps` output, which has observable
behaviors a port must match exactly:

- Integral floats serialize with a `.0` suffix: `1.0` → `1.0`.
- Negative zero serializes as `-0.0`.
- Floats use CPython's shortest-round-trip `repr` with fixed notation for
  `1e-4 ≤ |x| < 1e16` and exponent form outside that range (`1e-05`,
  `1e+16`).
- Non-ASCII characters are emitted as raw UTF-8 (`ensure_ascii=False`);
  U+2028 and U+2029 are NOT escaped.
- String escapes are exactly `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, plus
  `\u00XX` (lowercase hex) for the remaining C0 controls. DEL (U+007F) is
  NOT escaped. `/` is never escaped.
- Object keys are sorted by Unicode code point (Python string order):
  `￿` U+FFFF sorts BEFORE `𐀀` U+10000, unlike UTF-16 code-unit sorting.
- Integers have arbitrary precision and serialize in full decimal.

### 3.4 Strict parsing

`load_json_file` reads UTF-8 JSON with SkillLatch strictness:

- undecodable or unreadable files, and any `json.JSONDecodeError` →
  `invalid_json_file`;
- duplicate object keys → `duplicate_json_key`;
- the literals `NaN`, `Infinity`, `-Infinity` → `invalid_json_value`;
- overflow numbers such as `1e999` → `invalid_json_value` (via the float
  parser);
- files larger than 1 MiB (4 MiB for scan reports) → `limit_exceeded`;
- documents nesting deeper than 100 levels → `limit_exceeded` (raised during
  the canonicalization re-check after parsing).

### 3.5 Skill tree digest

`hash_skill_tree(skill_dir)` computes the skill digest:

1. The root must be a real directory, not a link or reparse point →
   `invalid_skill_tree`.
2. Walk with `os.walk(topdown=True, followlinks=False)`, re-raising walk
   errors; directory and file names are sorted at each level.
3. Every directory entry must be a real directory; every file entry must be
   a real regular file. Links, reparse points, and special files →
   `invalid_skill_tree`.
4. Each file's workspace-relative POSIX path is re-validated as a relative
   path (§4.3) → `invalid_path`.
5. Files are opened `O_RDONLY | O_BINARY | O_NOFOLLOW`, `fstat`-confirmed
   regular, and hashed in 1 MiB binary reads.
6. The walk aborts with `limit_exceeded` beyond 10000 files or 64 MiB total.
7. The inventory entries `{"path", "size", "sha256"}` (size in bytes,
   sha256 as lowercase hex without a prefix) are sorted by path; the tree
   digest is the digest of `{"schema": "skilllatch.tree.v1", "files":
   inventory}`.
8. OS errors surface as `invalid_skill_tree`.

## 4. Common types

### 4.1 Digest strings

Must match `^sha256:[0-9a-f]{64}$`. Violations are `invalid_schema`.

### 4.2 Timestamps

Must match `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$` and be a
valid calendar timestamp (parsed with `datetime.fromisoformat`). Violations
are `invalid_time`. The engine emits 0 fractional digits, or 6 when
microseconds are nonzero; 1–6 fractional digits are accepted on input.

### 4.3 Safe strings

A safe string is nonempty, contains no C0 control characters or DEL, and is
at most 256 characters (the default `_MAX_STRING_LENGTH`). Shape violations
are `invalid_schema`; the length cap is `limit_exceeded`.

### 4.4 Relative paths

A relative path is a safe string of at most 512 characters that:

- does not start with `/`;
- contains none of `\ : * ? < > | "`;
- has at most 32 `/`-separated components (`limit_exceeded` beyond);
- has no empty, `.`, or `..` component;
- has no component ending in a space or dot;
- has no component whose stem up to the first dot (right-stripped of
  spaces) is a Windows device name — `con`, `prn`, `aux`, `nul`, `conin$`,
  `conout$`, `com1`–`com9` (and superscript variants), `lpt1`–`lpt9`
  (likewise) — case-insensitive.

Violations are `invalid_path` (or `invalid_schema`/`limit_exceeded` from the
underlying safe-string checks).

### 4.5 Network origins and URLs

`_origin` normalizes a declared origin (manifest/grant) or a request URL to
a canonical origin string `https://host[:port]`. Rules, in check order:

1. Safe-string base, at most 2048 characters.
2. No leading/trailing whitespace; no backslash → `invalid_network_url`.
3. `urlsplit` must yield a parseable port and host →
   `invalid_network_url` ("invalid host or port").
4. Scheme must be `https`, with a nonempty netloc and host.
5. No username, password, or fragment.
6. Declarations are origin-only: no path, query, or fragment.
7. Request URL paths must not start with `//`.
8. The host must not end with a dot and must not contain `%`.
9. The host must be ASCII (use punycode for IDN), lowercased.
10. The host must be nonempty, contain no whitespace, and the port must not
    be 0.
11. An IPv6 host (contains `:`) is canonicalized to compressed form via
    `ipaddress.IPv6Address(...).compressed` and re-bracketed, so
    `https://[0:0:0:0:0:0:0:1]` and `https://[::1]` are the same origin.
12. A digit/dot-only host must be a canonical dotted-quad IPv4 address:
    exactly four all-digit labels, no leading zeros (except `0` itself),
    each ≤ 255; it is re-emitted via `ipaddress.IPv4Address`. Integer,
    shortened, octal-lookalike, and hex forms are rejected as disguise
    vectors.
13. Otherwise, no label may start with `0x` and no label may be all digits.
14. A non-IPv6 host is at most 253 characters and every label must match
    `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`.
15. Port 443 is dropped; any other port is kept.

Request URLs normalize to their origin for matching: the path and query are
discarded after validation. All violations are `invalid_network_url` except
the underlying safe-string and length checks.

### 4.6 Command argv

An argv is a nonempty array of at most 64 elements, each a safe string.
Shape violations are `invalid_schema`; the size cap is `limit_exceeded`.

## 5. Manifest (version 1)

Exact top-level keys: `version`, `skill`, `capabilities`. Parsing order:

1. exact key set (`invalid_schema`);
2. `version` must be the type-exact integer `1` (`unsupported_version`;
   `true` and `"1"` are not `1`);
3. `skill` must have exactly `name`, `digest`;
4. `skill.name` is a safe string;
5. `skill.digest` is a digest string;
6. `capabilities` (see below).

Capabilities have exactly `files`, `network`, `commands`:

- `files` has exactly `read` and `write`, each an array of at most 256 file
  rules (`limit_exceeded` beyond). A file rule has exactly `path` (a
  relative path, §4.4) and `recursive` (a boolean).
- `network` is an array of at most 256 declared origins (§4.5).
- `commands` is an array of at most 64 argv arrays (§4.6).

## 6. Grant (versions 1 and 2)

A version 1 grant has exactly: `version`, `session_id`, `task_id`,
`skill_digest`, `issued_at`, `expires_at`, `capabilities`. A version 2
grant adds `workspace_id` (a safe string pinning one workspace identity).

Normative parse-order asymmetry: the grant parser checks `version` (must be
the type-exact integer 1 or 2) BEFORE the exact key set, and selects the
key set by version; the manifest parser checks its exact key set BEFORE
`version`. A non-dict grant is `invalid_schema` with the version 1 key list
in the message regardless of intended version.

After key-set selection the order is: `workspace_id` (v2) → `issued_at` →
`expires_at` → window → `session_id` → `task_id` → `skill_digest` →
`capabilities` (same shape as §5).

- Window: `expires_at - issued_at` must be positive and at most 24 hours,
  else `invalid_grant_window`.
- Active interval: a grant is active for `issued_at <= t < expires_at`
  (half-open).

## 7. Requests

A request is an object with kind-specific exact keys:

- file: `session_id`, `task_id`, `kind` (`"file"`), `action`
  (`"read"`/`"write"`), `path` (relative path, §4.4);
- network: `session_id`, `task_id`, `kind` (`"network"`), `url` (§4.5);
- command: `session_id`, `task_id`, `kind` (`"command"`), `argv` (§4.6).

Code split: a non-dict request, a missing `kind`, or a `kind` outside
file/network/command is `invalid_request`; a wrong key set for a known kind
is `invalid_schema`. `session_id`/`task_id` safe-string checks run after
the kind-specific parse.

### 7.1 Workspace filesystem checks (file requests)

The request path is checked against the live workspace before any
capability comparison:

1. The workspace must be a real directory, not a link or reparse point →
   `invalid_workspace`.
2. Each existing path component (and the workspace root) must not be a link
   or reparse point → `unsafe_file_path`. Missing components are skipped.
3. The resolved target must stay within the resolved workspace root →
   `unsafe_file_path`.
4. The final component is checked with a single `lstat` (a separate
   `is_file()`/`lstat()` pair would leave an intra-check stat race): an
   existing regular file whose `st_nlink` is not 1 is denied as a
   hard-link risk → `unsafe_file_path`. A nonexistent target is allowed to
   proceed to capability checks (writes may create it).

## 8. Receipt (version 2) and historical version 1

### 8.1 Version 2 fields

| Field | Content |
| --- | --- |
| `version` | integer `2` |
| `allowed` | boolean decision |
| `reason_code` | registry code (§9) |
| `reason` | human-readable template instance |
| `evaluated_at` | RFC3339 UTC timestamp (§4.2) |
| `skill_digest` | digest or `null` |
| `workspace_id` | host-supplied identity or `null` |
| `workspace_binding` | `pinned`, `unpinned`, or `none` |
| `manifest_hash` | digest of the canonical manifest input |
| `grant_hash` | digest of the canonical grant input |
| `request_hash` | digest of the canonical request input |
| `digest` | digest of the canonical receipt minus this field |

Field semantics:

- `workspace_id` is the verbatim echo of the host-supplied value, even on
  failure and even when the value would itself be invalid as policy input —
  deliberate: the receipt binds what was supplied.
- `workspace_binding` is `pinned` iff the grant declares a workspace pin
  (on allow and deny receipts alike, including denials raised while parsing
  the rest of the grant, via a tolerant re-inspection of the raw grant);
  `unpinned` iff no pin is declared and the host supplied an identity
  (legacy v1 grant plus host id); `none` otherwise.
- `skill_digest` is `null` iff evaluation failed before or during tree
  hashing (an invalid host `workspace_id` string or an unreadable/invalid
  skill tree); every later failure carries the computed digest.
- The three input hashes always bind the exact canonical inputs, including
  inputs that failed to parse.
- CLI-synthesized denial receipts (the `check` command converting a
  `PolicyError` from unreadable or malformed input files) can only be
  `unpinned` or `none`, because the grant was never parsed, and may carry
  raised-only codes such as `invalid_json_file`.

### 8.2 Historical version 1

Version 1 receipts have exactly the ten fields of §8.1 minus `workspace_id`
and `workspace_binding`. Verifiers MUST accept version 1 receipts;
producers MUST NOT emit them.

## 9. Reason-code registry

Closed registry; adding a code requires updates to this SPEC, the
`schema/receipt-v2.json` enum, and the conformance suite. Surfaces:

- **receipt** — recorded in receipts returned by `evaluate()`;
- **raised-only** — only ever raised as `PolicyError` (or produced by a
  verifier/loader), never recorded in an `evaluate()` receipt;
- **dual** — raised on some entry paths, recorded in receipts on others.

### 9.1 Engine codes (core.REASON_CODES, 21)

| Code | Canonical reason template(s) | Raised by | Surface |
| --- | --- | --- | --- |
| `allowed` | "request matches the active capability grant" | `evaluate` (allow path) | receipt |
| `capability_not_granted` | "file {action} is not granted for this path"; "network origin {origin} is not granted"; "exact command argv is not granted" | `evaluate` (step 11) | receipt |
| `skill_digest_mismatch` | "skill bytes do not match both manifest and grant" | `evaluate` (step 6) | receipt |
| `grant_exceeds_manifest` | "grant contains an undeclared capability" | `evaluate` (step 7) | receipt |
| `grant_inactive` | "grant is not active at evaluation time" | `evaluate` (step 8) | receipt |
| `scope_mismatch` | "request session or task does not match grant" | `evaluate` (step 9) | receipt |
| `workspace_mismatch` | "grant is pinned to a different workspace" | `evaluate` (step 10) | receipt |
| `invalid_path` | "{label} must be a portable relative path"; "{label} contains a forbidden path component" | `_relative_path` | dual (receipts via `evaluate`; raised by public `hash_skill_tree`) |
| `invalid_network_url` | "network URL contains forbidden characters"; "network URL has an invalid host or port"; "network URL must use HTTPS and contain a host"; "network URL must not contain credentials or a fragment"; "declared network capability must be an origin only"; "network URL path must not start with //"; "network host must not end with a dot"; "network host must be ASCII; use punycode"; "network host is invalid"; "network IPv6 host is invalid"; "numeric host must be a canonical dotted-quad IPv4 address"; "network host must not use hex labels"; "DNS host labels must not be all digits" | `_origin` | receipt |
| `invalid_schema` | "{label} must have exactly: …"; "{label} must be a nonempty string without control characters"; "{label} must be a sha256: digest"; "file rule recursive must be boolean"; "files.{action} must be an array"; "network and commands must be arrays"; "command argv must be a nonempty array"; "grant must have exactly: capabilities, expires_at, issued_at, session_id, skill_digest, task_id, version" (non-dict grant, version 1 key list) | `_object`, `_string`, `_digest`, `_file_rule`, `_argv`, `_capabilities`, `_parse_grant` | receipt |
| `unsupported_version` | "{label} version must be one of: …"; "receipt version must be one of: 1, 2" | `_version`; `receipts.verify_receipt` | dual |
| `invalid_time` | "{label} must use YYYY-MM-DDTHH:MM:SS[.fraction]Z"; "{label} is not a valid timestamp"; "evaluation time must include a timezone" | `_parse_time`, `_utc_time` | dual (naive clock raises; grant timestamps land in receipts) |
| `invalid_grant_window` | "grant lifetime must be positive and at most 24 hours" | `_parse_grant` | receipt |
| `invalid_request` | "request must be an object"; "file action must be read or write"; "request kind must be file, network, or command" | `_request` | receipt |
| `invalid_skill_tree` | "skill directory must be a real directory"; "skill tree contains a link or special directory"; "skill tree contains a link or special file"; "skill tree contains a special file"; "skill directory could not be read safely" | `hash_skill_tree` | dual |
| `invalid_workspace` | "workspace must be a real directory" | `_safe_workspace_path` | receipt |
| `unsafe_file_path` | "file path passes through a link or reparse point"; "file path escapes workspace"; "file path could not be checked safely"; "file has multiple hard links" | `_safe_workspace_path` | receipt |
| `invalid_json_value` | "nonfinite numbers are invalid JSON inputs"; "NaN and Infinity are invalid JSON"; "JSON object keys must be strings"; "input must contain JSON values" | `_canonical_bytes`, `_strict_json_loads` | raised-only |
| `duplicate_json_key` | "duplicate JSON key: {key!r}" | `_unique_object` | raised-only |
| `invalid_json_file` | "cannot read valid JSON from {path}" | `load_json_file` | raised-only |
| `limit_exceeded` | "JSON nesting exceeds 100 levels"; "JSON input exceeds {max} bytes"; "{label} exceeds {max} characters"; "path exceeds 32 components"; "files.{action} exceeds 256 file rules"; "network exceeds 256 origins"; "commands exceed 64 entries"; "command argv exceeds 64 arguments"; "skill tree exceeds 10000 files"; "skill tree exceeds 64 MiB" | `_canonical_bytes`, `load_json_file`, `_string`, `_relative_path`, `_argv`, `_capabilities`, `hash_skill_tree` | dual |

### 9.2 Receipt and audit codes (receipts.RECEIPT_REASON_CODES)

All raised-only:

| Code | Canonical reason template(s) | Raised by |
| --- | --- | --- |
| `invalid_receipt` | "receipt must be a JSON object"; "receipt keys mismatch (…)"; "receipt is not canonical JSON (…)"; "receipt allowed must be boolean"; "receipt {label} must be a nonempty string"; "receipt reason_code must not contain control characters"; "receipt evaluated_at must use YYYY-MM-DDTHH:MM:SS[.fraction]Z"; "receipt evaluated_at is not a valid timestamp"; "receipt skill_digest must be null or a sha256: digest"; "receipt workspace_binding must be pinned, unpinned, or none"; "receipt workspace_id must be null or a string"; "receipt {label} must be a sha256: digest" | `verify_receipt` |
| `receipt_digest_mismatch` | "receipt digest does not match its contents" | `verify_receipt` |
| `invalid_audit_log` | "audit log must be a nonempty array"; "line {i}: audit line must have exactly: line, line_digest, prev_digest, receipt"; "line {i}: line number gap or renumbering"; "line {i}: line_digest must be a sha256: digest"; "audit line number must be a positive integer"; "audit line 1 must not have a previous digest"; "audit line {n} needs the previous line digest"; "cannot read audit log from {path}"; "line {n}: blank line in audit log"; "line {n}: invalid JSON (…)" | `make_audit_line`, `verify_audit_log`, `load_audit_log` |
| `audit_chain_mismatch` | "line {i}: previous digest does not match the chain"; "line {i}: line digest does not match its contents" | `verify_audit_log` |

### 9.3 Scan advisory codes (skillspector.SCAN_REASON_CODES)

Both raised-only:

| Code | Canonical reason template(s) | Raised by |
| --- | --- | --- |
| `invalid_scan_report` | "scan report could not be loaded ({code}: {reason})"; "scan report must be a JSON object" | `load_scan_report` |
| `scan_digest_mismatch` | "scan report subject does not match the skill tree" | `load_scan_report` |

Footnote: `no_tool_registered` is adapter-level only
(examples/host_adapter.py), returned in host outcomes; it never appears
inside a receipt.

## 10. Evaluation pipeline (normative order)

`evaluate(skill_dir, workspace, manifest, grant, request, *, at=None,
workspace_id=None)` runs in exactly this order. Step numbering matches the
implementation.

**Pre-receipt phase (raises, never produces a receipt):**

- **0a.** Canonical bytes are computed over `manifest`, `grant`, and
  `request`. Non-JSON Python values or nonfinite floats raise
  `invalid_json_value`. This is why malformed direct Python values raise
  while valid JSON-shaped inputs always get a receipt.
- **0b.** The clock is resolved (`at` or `datetime.now(UTC)`) and must be
  timezone-aware, else `invalid_time` raises. Library callers MUST treat a
  raised `PolicyError` as a denial.

**Decision phase (any `PolicyError` becomes a deny receipt):**

1. The host `workspace_id`, when present, must be a safe string
   (`invalid_schema` / `limit_exceeded`).
2. `hash_skill_tree(skill_dir)` (§3.5) → `invalid_skill_tree`,
   `invalid_path`, `limit_exceeded`. An unreadable tree therefore beats a
   bad manifest.
3. Parse the manifest (§5): exact keys → version → skill keys → name →
   digest → capabilities.
4. Parse the grant (§6): version → exact keys → workspace pin → timestamps
   → window → session/task → skill digest → capabilities.
5. Parse the request (§7), including the workspace filesystem checks
   (§7.1). A malformed request therefore beats a digest mismatch.
6. Digest triple equality: the tree digest must equal both the manifest's
   `skill.digest` and the grant's `skill_digest`, else
   `skill_digest_mismatch`.
7. Grant ⊆ manifest per capability kind (file rules may narrow by path and
   recursiveness; origins and argvs must be literal subsets), else
   `grant_exceeds_manifest`.
8. The grant must be active at the evaluation time (half-open interval),
   else `grant_inactive`.
9. Request `session_id`/`task_id` must equal the grant's, else
   `scope_mismatch`.
10. A v2 grant pin must equal the host `workspace_id` (a missing host
    identity mismatches), else `workspace_mismatch`.
11. Per-kind capability: the file path must fall within a granted rule for
    the action; the normalized origin must be granted; the exact argv must
    be granted — else `capability_not_granted`.

Two deliberate orderings to preserve in ports: request parsing (step 5)
precedes digest equality (step 6), and tree hashing (step 2) precedes
manifest parsing (step 3).

## 11. Versioning and extensibility

- Versions are type-exact integers: `1` is not `true`, `"1"`, or `1.0`.
- An unknown version is `unsupported_version`.
- Unknown keys are `invalid_schema`; every document has an exact key set.
- New fields require a version bump, not a key-set extension.
- Registries (reason codes, workspace bindings, request kinds, file
  actions) are closed; see §9 for the update rule.
- Digest agility lives in the `sha256:` prefix: a future algorithm uses a
  new prefix and new document versions.

## 12. Determinism guarantees

- Same inputs plus same clock ⇒ byte-identical receipt. The conformance
  runner evaluates every case twice and requires identical receipts.
- The tree digest is stable across operating systems: sorted inventory,
  POSIX relative paths, binary reads only.
- Receipt content depends on the inputs, the clock, the tree bytes, and —
  through `reason_code` alone — the workspace filesystem state (§7.1): the
  filesystem can change WHICH denial is produced, never the hashes, which
  bind the canonical inputs.
- Caveats:
  - CLI-synthesized denial receipts embed file paths in `reason`
    ("cannot read valid JSON from {path}") and are not cross-platform.
  - The clock is host-owned; `--at` is a diagnostic override.
  - The §3.3 float quirks are latent: no v1/v2 document field carries
    non-integral numbers, so current receipts never exercise them.

## 13. Receipt verification and the audit log

### 13.1 `verify_receipt` (offline)

Algorithm: receipt must be a dict; `version` must be the type-exact integer
1 or 2 (`unsupported_version`); exact key set per version (§8)
(`invalid_receipt`, with a missing/extra detail); the receipt must
canonicalize (`invalid_receipt`); `allowed` boolean; `reason_code` and
`reason` nonempty strings, `reason_code` free of control characters;
`evaluated_at` matching §4.2 and calendar-valid; `skill_digest` null or a
digest; v2 additionally requires `workspace_binding` in
pinned/unpinned/none and `workspace_id` null or a string (content
unconstrained — §8.1); the four digest fields digest-shaped; finally the
`digest` must equal the digest of the receipt minus `digest`
(`receipt_digest_mismatch`). Returns `{"valid": true, "version": v,
"digest": d}`.

Guarantee: internal consistency only — the digest matches the canonical
body. No statement about authorship, approval, or whether any action
occurred.

### 13.2 Audit log format (`skilllatch.audit.v1`)

A JSONL file, UTF-8, one audit line per text line. Each line is a JSON
object with exactly `line`, `receipt`, `prev_digest`, `line_digest`:

- line 1 carries `prev_digest: null`;
- line *i* carries `prev_digest` = the `line_digest` of line *i*−1;
- `line_digest` is the digest of the canonical object `{"line": n,
  "prev_digest": p, "receipt": r}`.

`load_audit_log` tolerates exactly one trailing newline and a per-line
carriage return, rejects blank lines, and parses each line with §3.4
strictness (`invalid_audit_log`). `audit_line_to_json` serializes one line
as canonical compact JSON with no trailing newline.

### 13.3 `verify_audit_log`

Per line, in order: exact key set; `prev_digest` equals the running chain
(`audit_chain_mismatch`); line numbers are sequential from 1
(`invalid_audit_log`); the embedded receipt passes §13.1 (the failing code
is re-raised with a `line {i}:` prefix); `line_digest` is digest-shaped;
the recomputed line digest matches (`audit_chain_mismatch`). Returns
`{"valid": true, "lines": n}`.

### 13.4 Honesty

The audit log is tamper-EVIDENT, not tamper-proof. There are no signatures
or keys: an attacker who rewrites the whole file can rechain it. The format
deters silent single-record edits and detects edits, gaps, deletions,
truncation, and reordering — nothing more.

## 14. Deterministic resource limits

| Input | Limit |
| --- | --- |
| JSON input file (`load_json_file`) | 1 MiB (4 MiB for scan reports) |
| JSON nesting depth (arrays/objects, root = 1) | 100 levels |
| Safe strings (`session_id`, `task_id`, `workspace_id`, argv elements, …) | 256 characters |
| Relative path | 512 characters, 32 components |
| Network origin / URL | 2048 characters |
| File rules per action | 256 |
| Network origins | 256 |
| Commands | 64 entries |
| Arguments per argv | 64 |
| Skill tree | 10000 files, 64 MiB total |

Violations surface as `limit_exceeded`. Rationale: bound host CPU and
memory per decision regardless of attacker-controlled input size. The depth
cap also makes parse outcomes portable across hosts with default
interpreter limits; hosts running with reduced recursion limits may reject
some ≤100-deep documents with `invalid_json_file` instead.

## 15. Conformance

The data-driven suite in [conformance/](../conformance/README.md) covers
every engine reason code except `unsafe_file_path` (unit tests only — it
needs symlink/hard-link privileges). `expect_digest` pins exact receipt
digests for selected cases and is regenerated only on a deliberate
receipt-format change. [tests/test_golden_receipts.py](../tests/test_golden_receipts.py)
pins byte-exact receipts for the `examples/` fixtures.
[schema/](../schema/README.md) holds documentation-grade JSON Schemas; the
subset checker in [tests/test_schemas.py](../tests/test_schemas.py) verifies
fixtures against their structural shape. The parser remains authoritative
everywhere.

## 16. Security considerations

See [THREAT_MODEL.md](THREAT_MODEL.md) for the trust boundary, check/use
races, and receipt proof limits. In brief: a receipt proves only that a
deterministic decision was produced over the supplied inputs — not that an
action occurred, not that a denial prevented one, and not authorship; the
audit log is tamper-evident, not tamper-proof (§13.4); `request_hash` is an
unsalted hash of the canonical request, so requests must not contain
secrets.
