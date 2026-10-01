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

## Workspace identity binding

Version 2 grants may pin a workspace identity, and version 2 receipts record the host-observed identity and how it was bound (`pinned`, `unpinned`, or `none`). A pinned grant evaluated with a different or missing host identity is denied with `workspace_mismatch`. This blocks cross-workspace replay only when distinct workspaces use distinct host-asserted identities: the identifier is host-asserted, not self-authenticating, and reusing one identifier for two directories reopens the ambiguity it was meant to close. Version 1 grants carry no pin; they still evaluate, with binding `none` or `unpinned` on the receipt.

## Check/use races by action kind

The decision is a point-in-time statement; the host must close the gap between check and use for each action kind.

- **File:** a hard-linked file with multiple names is denied, but a link created after the check is a residual race. The host should open the target through a checked directory handle immediately before use rather than reopening by path later.
- **Network:** DNS can rebind between the check and the connection. The host should pin the resolution used at decision time and never follow cross-origin redirects silently.
- **Command:** the host should resolve the absolute executable path at check time, verify it against PATH drift, and execute the exact argument vector without a shell.
- **Skill tree:** the bytes are snapshotted at approval and the digest is re-verified at decision time; a change between decision and dispatch is outside the receipt's scope.

## Receipt proof limits

A receipt proves only that a deterministic decision was produced over the supplied inputs. It is not proof that an action occurred, not proof that a denial prevented one, and not proof of authorship or approval. The digest is a SHA-256 over canonical JSON, not a signature; receipts are replayable JSON and carry no freshness or origin guarantee on their own. A denial for unparseable inputs binds only what could be read, not the unreadable bytes. `request_hash` is an unsalted hash of the canonical request: do not put secrets in requests.

## Integration direction

[examples/host_adapter.py](../examples/host_adapter.py) is the reference gate: its tests demonstrate that a denied request never reaches a tool, and its scripted demo prints those denials end to end. Its tools are simulated; a production integration must perform the real interception. An integration should call SkillLatch at a real tool boundary, identify the active instruction artifacts as host-observed context, include the tool identity and version, and retain the resulting decision. It should never infer that a skill caused a call solely because its text was loaded. For MCP-served skills, preserve server identity and URI, and follow the existing [MCP Skills security requirements](https://modelcontextprotocol.io/extensions/skills/overview). Explore interceptor hooks with the [MCP Interceptors Working Group](https://modelcontextprotocol.io/community/working-groups/interceptors) before proposing new wire fields.
