# JSON schemas (documentation-grade)

This directory holds JSON Schema 2020-12 descriptions of the SkillLatch
wire formats, for external tooling and editor support:

- `manifest-v1.json` — capability manifest (version 1)
- `grant-v1.json` — session/task grant (version 1, no workspace pin)
- `grant-v2.json` — session/task grant (version 2, workspace pin)
- `request.json` — action request (file / network / command, `oneOf`)
- `receipt-v2.json` — decision receipt (version 2)

**The reference parser in [skilllatch/core.py](../skilllatch/core.py) is
authoritative.** These schemas exist so editors and external verifiers can
catch gross shape errors; they are deliberately a *recognizable subset* of
what the parser enforces. Where a schema and the parser disagree, the parser
wins — report discrepancies as bugs.

## Known looseness vs the parser

JSON Schema 2020-12 (and the even smaller subset checked by
[tests/test_schemas.py](../tests/test_schemas.py)) cannot express every
parser rule. Each file records its gaps in `$comment` fields; the full list:

- **Calendar validity:** timestamps are matched against the RFC3339 UTC
  pattern only; impossible dates (e.g. month 13) still parse there.
- **Grant window:** the rule that `expires_at - issued_at` must be positive
  and at most 24 hours is not expressible.
- **Relative paths:** the RELPATH pattern rejects absolute paths, `//`,
  trailing `/`, `.`/`..` components, and the forbidden character set, but
  not Windows device names (`con`, `nul`, `com1`, …) or components ending
  in a space or dot.
- **Network host rules:** the patterns enforce `https://` and an origin-only
  shape for declarations, but not the parser's full host validation (ASCII
  or punycode only, DNS label shape and length, IPv4 canonical dotted-quad
  with disguise forms rejected, IPv6 canonicalization, port rules, host
  length caps).
- **Digest self-consistency:** a receipt's `digest` equals the sha256 of its
  canonical body; no schema can express that. Use
  `skilllatch.receipts.verify_receipt`.
- **Duplicate keys / nonfinite numbers:** invisible to JSON Schema; the
  strict parser rejects both.
- **Integer domain:** JSON Schema `integer` accepts `1.0`; the parser
  requires type-exact ints (and rejects `true` as a version).
- **Receipt `reason_code` enum:** lists every engine code, including
  `duplicate_json_key`, `invalid_json_file`, and `invalid_json_value`, which
  the evaluation pipeline raises but never records — they appear only in
  CLI-synthesized denial receipts.
- **Receipt `workspace_id`:** constrained only to `string|null` because the
  receipt echoes the host-supplied identity verbatim.
- **Limits:** string/array/tree size caps (§14 of docs/SPEC.md) are not
  expressed.

## Why the capabilities object is inlined

`manifest-v1.json`, `grant-v1.json`, and `grant-v2.json` share one
`capabilities` shape. It is copied inline into each file (rather than shared
through `$defs`/`$ref` or an external `$id`) so that every schema file is
fully self-contained: editors and validators can load any single file
without resolving references, and no file carries a network-resolvable
identifier. Keep the three copies byte-identical when editing.

## Relationship to the test subset checker

[tests/test_schemas.py](../tests/test_schemas.py) ships a hand-rolled
checker for a small JSON Schema subset (`type`, `required`,
`additionalProperties: false`, `properties`, `items`, `oneOf`) and
deliberately ignores `const`, `enum`, `pattern`, `minLength`, and `$ref`.
It verifies that repository fixtures and live receipts satisfy the
structural shape these schemas describe; keyword-level validity remains the
engine's job.
