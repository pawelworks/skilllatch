# SkillLatch

SkillLatch is an early, local reference implementation for deciding whether an AI agent skill may make a particular tool request during a particular task. It is designed for a host or interceptor to call **before** a file, network, or command action. The decision is deterministic and recorded as JSON.

The motivating example is a seemingly helpful skill that asks to read unrelated client files or send data to an unfamiliar endpoint. A scanner can flag suspicious content before installation. SkillLatch explores a complementary question at use time: does this specific requested action fit both the skill's declared capabilities and the narrower grant the user approved for this session?

## Status

Prototype, 0.1 draft. No production use, independent audit, external adoption, or foundation affiliation is claimed. This repository does not reproduce NVIDIA SkillSpector's detection engine or its branding. SkillLatch does not execute a skill or intercept host tools on its own. A host must supply truthful request metadata and honor the decision before performing the action. For valid JSON inputs, the receipt binds their canonical form to the decision and evaluation time; it is not proof that an action occurred or was prevented. A structured denial for malformed JSON does not bind the unreadable input bytes.

The repository now also contains: a reference gated host ([examples/host_adapter.py](examples/host_adapter.py)) whose tools are **simulated** — it demonstrates gate wiring, not production interception; a scripted, self-checking terminal demo ([examples/demo.py](examples/demo.py)); a data-driven conformance fixture suite ([conformance/](conformance/README.md)); and an offline advisory loader for SkillSpector-shaped JSON scan reports (`load_scan_report`), which reads one local file, performs no network I/O, and never changes a policy decision. Illustrative additions: an example validator-style interceptor for MCP-shaped `tools/call` messages ([examples/mcp_interceptor.py](examples/mcp_interceptor.py)), and a first implementation of the host-originated context provenance envelope (`build_context`, [skilllatch/context.py](skilllatch/context.py)).

## How it works

1. A host identifies the exact skill files it approved and computes a content digest.
2. A capability manifest declares which files, HTTPS origins, and exact command arguments the skill may request.
3. The user or host issues a time-limited grant for one task and session. It may narrow, but never widen, the manifest. A version 2 grant may also pin one workspace identity.
4. Before a tool call, the host passes the request to SkillLatch together with the workspace identity it observes. SkillLatch checks the digest, grant, workspace pin, and requested action; unknown actions are denied. A pinned grant presented for a different workspace — or with no host workspace identity — is denied with `workspace_mismatch`.
5. The host enforces the returned decision and retains the JSON receipt if useful for review. Receipts are version 2.

The first implementation is a local CLI and Python library with no service or API key. See [the threat model](docs/THREAT_MODEL.md) for the boundaries.

Library callers can import `evaluate` from `skilllatch`, passing the host-observed identity as the `workspace_id=` keyword. Valid JSON-shaped inputs produce an allow/deny decision; malformed direct Python values or an invalid clock may raise `PolicyError`, and a host adapter **must** treat that exception as a denied action. `load_scan_report` attaches a SkillSpector-shaped scan report as advisory metadata: it reads one local JSON file, performs no network I/O, and never changes a decision. SkillLatch never transmits skill content, scan reports, or secrets to any scanner or endpoint; attaching a report is the host's choice.

## Quick start

Python 3.11 or newer is required. From the repository root:

```console
python -m skilllatch digest --skill-dir examples/chef-helper
python -m skilllatch check --skill-dir examples/chef-helper --workspace examples/workspace --manifest examples/manifest.json --grant examples/grant.json --request examples/allowed-request.json --at 2026-10-01T12:00:00Z --workspace-id chef-demo-workspace
```

The check prints a JSON decision. Exit codes: `0` allowed, `2` denied (policy denial, including unreadable or malformed input files), `3` engine error in the `digest` command, `64` usage error. The offline verification commands use `0` valid, `2` invalid, `64` usage error. `--at` makes the fixed-time fixture reproducible; a production host must use a trusted current clock. `--workspace-id` is the host-observed workspace identity; the example grant is pinned to `chef-demo-workspace`, so omitting the flag (or passing a different value) denies the same request with `workspace_mismatch`. The example files are illustrative and may be inspected without running a skill. Run the tests with `python -m unittest discover -s tests -v`.

## Verify receipts and audit logs offline

```console
python -m skilllatch verify --receipt receipt.json
python -m skilllatch verify-log --log audit.jsonl
```

`verify` checks one receipt's shape and recomputes its digest; `verify-log` checks a JSONL audit log's numbering, per-line receipts, and hash chain, printing `{"valid":true,"lines":n}` on success. Both are fully offline: no network, no clock, and no original policy inputs are needed; they prove internal consistency only. The audit log is tamper-**evident**, not tamper-proof — there are no signatures or keys, and an attacker who rewrites the whole file can rechain it. The format deters silent single-record edits and detects edits, gaps, deletions, truncation, and reordering — nothing more. The same checks are available as the library functions `verify_receipt`, `make_audit_line`, `verify_audit_log`, `load_audit_log`, and `audit_line_to_json`.

## Run the gated-host demo

```console
python examples/demo.py
python examples/demo.py --quiet
```

The demo stages the example skill and workspace in a temporary directory, walks seven scripted requests through the reference host — one allowed read and six denials, including a grant replayed on another workspace — and asserts that no denied request ever reaches a tool. It then chains the seven receipts into a tamper-evident audit log, writes it to disk, verifies it offline, and confirms that a flipped receipt is detected. It prints `7 steps: 1 allowed+dispatched, 6 denied, 0 denied requests reached a tool; audit log 7 lines verified` and exits `0` when every expectation holds, `1` on any mismatch. `--quiet` suppresses the narration but keeps the assertions and the summary line. The tools are simulated: the fetch and command stubs perform no network I/O and spawn no subprocess.

### Indicative local timing

```console
python examples/benchmark.py --iterations 2000 --warmup 200
```

This prints indicative local timing of `evaluate()`; it is **not a benchmark claim**. It measures the full decision path over cached in-memory policy inputs against the repository's example skill and workspace. Every iteration re-runs `evaluate()`, which includes a full `hash_skill_tree` rehash of the skill directory — that filesystem cost is part of every decision and is never amortized. Numbers vary with machine, OS, filesystem cache, and Python build.

## Illustrative MCP-shaped interceptor example

[examples/mcp_interceptor.py](examples/mcp_interceptor.py) gates MCP-shaped `tools/call` request messages: a host-supplied mapping derives a SkillLatch request from the tool name and arguments; session, task, and workspace identity come only from host-side state, never from message content; unmapped tools and malformed messages fail closed with `unmapped_tool` or `invalid_message`; audit mode reports policy denials as `warn` without blocking. It is informed by the draft MCP Interceptors proposal (SEP-2624); it implements no MCP transport, speaks no JSON-RPC on the wire, and is not an implementation of that draft or of the MCP Skills extension. Tools are simulated; the example demonstrates gate wiring, not production interception.

## Context provenance envelope (skilllatch.context.v1)

`build_context()` ([skilllatch/context.py](skilllatch/context.py)) records which instruction artifacts were active at request time: skill digests with a `local_dir` or `mcp` (server identity plus URI) source, project-instruction digests, tool identity and schema digest, a reduced advisory identity, the grant hash, and a self-digest. Attribution is the constant `unknown` — presence of instructions does not establish they caused the request. The envelope carries digests and labels only, never file paths, instruction text, tool arguments, or secrets. Pass it as `context=` to `GatedHost` (constructor or per-dispatch) to copy it into outcomes next to `advisory`. This is a first implementation of the foundation-brief research increment, not a standard.

[docs/SPEC.md](docs/SPEC.md) is the normative formats-and-semantics document for implementers of verifiers, ports, and host adapters. [schema/](schema/README.md) holds documentation-grade JSON Schemas for editor and tooling support; the reference parser in [skilllatch/core.py](skilllatch/core.py) remains authoritative.

## Receipts (v2)

A receipt records: `version` (2), `allowed`, `reason_code`, `reason`, `evaluated_at`, `skill_digest`, `workspace_id`, `workspace_binding`, `manifest_hash`, `grant_hash`, `request_hash`, and `digest`. `workspace_id` is the host-observed value supplied at evaluation (or `null`). `workspace_binding` is `pinned` when the grant declares a workspace pin (whether the decision allows or denies), `unpinned` when a legacy v1 grant was evaluated with a host-supplied identity, and `none` when neither side supplied one. The `digest` is `sha256:` of the canonical JSON of the receipt minus the `digest` field itself; it can be recomputed offline with `json.dumps(receipt_without_digest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8. Version 1 grants still evaluate; their receipts are version 2 with binding `none` or `unpinned`.

## Network origin canonicalization

Origins are canonicalized before comparison so that disguise forms cannot launder an unapproved destination past a reviewer. IPv6 hosts are re-emitted in compressed form, so `https://[0:0:0:0:0:0:0:1]` and `https://[::1]` are the same origin. An IPv4 host must be a canonical dotted-quad: integer (`2130706433`), shortened (`127.1`), octal-lookalike (`0177.0.0.1`, `010.0.0.1`), and hex (`0x7f.0.0.1`) forms are rejected with `invalid_network_url`, as are all-digit labels in DNS names (`example.123`). A valid `https://127.0.0.1` works like any other origin when declared and granted.

## Deterministic resource limits

Parsing and validation enforce fixed limits so every decision bounds host CPU and memory, and so parse outcomes are identical across hosts. A violation denies with reason code `limit_exceeded` (raised as `PolicyError` by `load_json_file`).

| Input | Limit |
| --- | --- |
| JSON nesting depth (arrays/objects, root = 1) | 100 levels |
| JSON input file size (`load_json_file`) | 1 MiB (4 MiB for scan reports) |
| Strings (`session_id`, `task_id`, `workspace_id`, command arguments, …) | 256 characters |
| Network origin / URL | 2048 characters |
| Relative path | 512 characters, 32 components |
| File rules per action, network origins | 256 each |
| Commands | 64 entries; 64 arguments per argv |
| Skill tree | 10000 files, 64 MiB total |

## Relation to existing work

[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) already scans skill packages for suspicious patterns, with optional semantic analysis and machine-readable output. It can be used before installing or approving a skill. The [MCP Skills extension](https://modelcontextprotocol.io/extensions/skills/overview) already specifies per-file digests and content-bound host approval for skills served over MCP. SkillLatch does not claim those mechanisms as inventions. Its narrow experiment is an action-level grant and decision receipt that an integrating host can use after approving a skill. The [MCP Security Interest Group](https://modelcontextprotocol.io/community/interest-groups/security) lists runtime drift and auditability among its active discussion topics; any standards proposal should be developed with the relevant MCP groups.

See [the foundation brief](docs/FOUNDATION_BRIEF.md) for the proposed research scope and evidence still needed before an AAIF proposal. SkillLatch is separate from [RelayReady](https://github.com/pawelworks/relayready); no shared wire identifier or existing foundation application is changed.

The [origin and evidence record](docs/PROVENANCE.md) explains the video inspiration and the limits of the example results.

## License and contact

MIT licensed. Maintainer: Pavel Mihai Lucian, PAWELWORKS S.R.L., Romania. Project contact: <lucian.pavel@pawelworks.com>.
