# Threat model and limits

## Intended boundary

SkillLatch is a policy decision component. A trusted host asks it about one proposed action before performing that action. The host is responsible for obtaining user consent, identifying the active skill and session, restricting execution to the granted environment, and refusing a denied action. An untrusted skill must not be allowed to forge the host's request or edit the grant.

The prototype handles three action shapes: workspace-relative file reads/writes, HTTPS destinations, and exact command argument vectors. The manifest is an upper bound; the session grant may narrow it. Missing or malformed values deny the request. The implementation does not run commands, open network connections, or invoke code from the target skill.

## Threats it is meant to expose

- A skill requests a file outside the workspace or outside its approved path.
- A skill tries to send data to a destination absent from its grant.
- A skill asks for a command or arguments different from what was approved.
- A skill or grant changes after approval, or a grant is used for another task, session, or time interval.
- An ambiguous path, symlink, or malformed JSON would make an approval broader than intended.

## Outside this prototype

SkillLatch cannot detect malicious text in `SKILL.md`, infer a skill's true intent, or prove that input metadata is genuine. It does not monitor processes, intercept every host tool, control a browser, validate TLS connections, inspect command side effects, or stop code that runs outside an integrating host's gate. An allowed request can still be unsafe. A denied request is only blocked if the host enforces the decision.

The host must execute an approved command as the exact argument vector it checked, without passing it through a shell or reinterpreting its arguments. It must also route every relevant tool path through the same gate. This prototype does not supply that host integration.

### Deterministic resource limits

Parsing and validation enforce fixed limits (JSON nesting ≤ 100 levels; JSON input files ≤ 1 MiB, scan reports ≤ 4 MiB; strings ≤ 256 characters; origins ≤ 2048 characters; paths ≤ 512 characters and 32 components; ≤ 256 file rules per action and ≤ 256 origins; ≤ 64 commands and ≤ 64 argv elements; skill trees ≤ 10000 files and ≤ 64 MiB). Violations surface as `limit_exceeded`. The rationale is to bound host CPU and memory per decision, regardless of attacker-controlled input size. The JSON depth cap of 100 also makes parse outcomes portable across hosts with default interpreter limits; note that hosts running with reduced recursion limits may reject some ≤ 100-deep documents with `invalid_json_file` instead.

## Workspace identity binding

Version 2 grants may pin a workspace identity, and version 2 receipts record the host-observed identity and how it was bound (`pinned`, `unpinned`, or `none`). A pinned grant evaluated with a different or missing host identity is denied with `workspace_mismatch`. This blocks cross-workspace replay only when distinct workspaces use distinct host-asserted identities: the identifier is host-asserted, not self-authenticating, and reusing one identifier for two directories reopens the ambiguity it was meant to close. Version 1 grants carry no pin; they still evaluate, with binding `none` or `unpinned` on the receipt.

## Check/use races by action kind

The decision is a point-in-time statement; the host must close the gap between check and use for each action kind.

- **File:** a hard-linked file with multiple names is denied, but a link created after the check is a residual race. The final-component check uses a single `lstat`, but closing the race still requires the host to open the target through a checked directory handle (open-by-handle) immediately before use rather than reopening by path later. `st_nlink` semantics are filesystem-dependent: a filesystem reporting `nlink` 0 or greater than 1 for all files causes false denies, while one always reporting 1 makes the guard inert.
- **Network:** origin canonicalization keeps numeric, hex, and octal disguise forms from reaching an approver, but DNS can still rebind between the check and the connection. The host should pin the resolution used at decision time and never follow cross-origin redirects silently.
- **Command:** the host should resolve the absolute executable path at check time, verify it against PATH drift, and execute the exact argument vector without a shell.
- **Skill tree:** the bytes are snapshotted at approval and the digest is re-verified at decision time; a change between decision and dispatch is outside the receipt's scope.

## Receipt proof limits

A receipt proves only that a deterministic decision was produced over the supplied inputs. It is not proof that an action occurred, not proof that a denial prevented one, and not proof of authorship or approval. The digest is a SHA-256 over canonical JSON, not a signature; receipts are replayable JSON and carry no freshness or origin guarantee on their own. A denial for unparseable inputs binds only what could be read, not the unreadable bytes. `request_hash` is an unsalted hash of the canonical request: do not put secrets in requests.

## Integration direction

[examples/host_adapter.py](../examples/host_adapter.py) is the reference gate: its tests demonstrate that a denied request never reaches a tool, and its scripted demo prints those denials end to end. Its tools are simulated; a production integration must perform the real interception. [examples/mcp_interceptor.py](../examples/mcp_interceptor.py) is an illustrative validator-style example informed by the draft MCP Interceptors proposal (SEP-2624): it maps MCP-shaped `tools/call` messages onto SkillLatch requests via a host-supplied mapping, takes identity only from host-side state, fails closed on unmapped tools and malformed messages, and deliberately omits the draft's failOpen option. [skilllatch/context.py](../skilllatch/context.py) is a first implementation of the host-originated context provenance envelope (skilllatch.context.v1): it records active instruction artifacts (skill digests and sources, project-instruction digests, tool identity, advisory identity, grant hash) with attribution fixed to `unknown` — presence of instructions does not establish they caused the request. An integration should call SkillLatch at a real tool boundary, identify the active instruction artifacts as host-observed context, include the tool identity and version, and retain the resulting decision. It should never infer that a skill caused a call solely because its text was loaded. For MCP-served skills, preserve server identity and URI, and follow the existing [MCP Skills security requirements](https://modelcontextprotocol.io/extensions/skills/overview). Explore interceptor hooks with the [MCP Interceptors Working Group](https://modelcontextprotocol.io/community/working-groups/interceptors) before proposing new wire fields.
