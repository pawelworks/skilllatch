# SkillLatch

SkillLatch is an early, local reference implementation for deciding whether an AI agent skill may make a particular tool request during a particular task. It is designed for a host or interceptor to call **before** a file, network, or command action. The decision is deterministic and recorded as JSON.

The motivating example is a seemingly helpful skill that asks to read unrelated client files or send data to an unfamiliar endpoint. A scanner can flag suspicious content before installation. SkillLatch explores a complementary question at use time: does this specific requested action fit both the skill's declared capabilities and the narrower grant the user approved for this session?

## Status

Prototype, 0.1 draft. No production use, independent audit, external adoption, or foundation affiliation is claimed. This repository does not reproduce NVIDIA SkillSpector's detection engine or its branding. SkillLatch does not execute a skill or intercept host tools on its own. A host must supply truthful request metadata and honor the decision before performing the action. For valid JSON inputs, the receipt binds their canonical form to the decision and evaluation time; it is not proof that an action occurred or was prevented. A structured denial for malformed JSON does not bind the unreadable input bytes.

## How it works

1. A host identifies the exact skill files it approved and computes a content digest.
2. A capability manifest declares which files, HTTPS origins, and exact command arguments the skill may request.
3. The user or host issues a time-limited grant for one task and session. It may narrow, but never widen, the manifest.
4. Before a tool call, the host passes the request to SkillLatch. SkillLatch checks the digest, grant, and requested action; unknown actions are denied.
5. The host enforces the returned decision and retains the JSON receipt if useful for review.

The first implementation is a local CLI and Python library with no service or API key. See [the threat model](docs/THREAT_MODEL.md) for the boundaries.

Library callers can import `evaluate` from `skilllatch`. Valid JSON-shaped inputs produce an allow/deny decision; malformed direct Python values or an invalid clock may raise `PolicyError`. A host adapter must treat that exception as a denied action.

## Quick start

Python 3.11 or newer is required. From the repository root:

```console
python -m skilllatch digest --skill-dir examples/chef-helper
python -m skilllatch check --skill-dir examples/chef-helper --workspace examples/workspace --manifest examples/manifest.json --grant examples/grant.json --request examples/allowed-request.json --at 2026-10-01T12:00:00Z
```

The check prints a JSON decision and exits `0` for an allowed request or `2` for a denied one. `--at` makes the fixed-time fixture reproducible; a production host must use a trusted current clock. The example files are illustrative and may be inspected without running a skill. Run the tests with `python -m unittest discover -s tests -v`.

## Relation to existing work

[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) already scans skill packages for suspicious patterns, with optional semantic analysis and machine-readable output. It can be used before installing or approving a skill. The [MCP Skills extension](https://modelcontextprotocol.io/extensions/skills/overview) already specifies per-file digests and content-bound host approval for skills served over MCP. SkillLatch does not claim those mechanisms as inventions. Its narrow experiment is an action-level grant and decision receipt that an integrating host can use after approving a skill. The [MCP Security Interest Group](https://modelcontextprotocol.io/community/interest-groups/security) lists runtime drift and auditability among its active discussion topics; any standards proposal should be developed with the relevant MCP groups.

See [the foundation brief](docs/FOUNDATION_BRIEF.md) for the proposed research scope and evidence still needed before an AAIF proposal. SkillLatch is separate from [RelayReady](https://github.com/pawelworks/relayready); no shared wire identifier or existing foundation application is changed.

The [origin and evidence record](docs/PROVENANCE.md) explains the video inspiration and the limits of the example results.

## License and contact

MIT licensed. Maintainer: Pavel Mihai Lucian, PAWELWORKS S.R.L., Romania. Project contact: <lucian.pavel@pawelworks.com>.
