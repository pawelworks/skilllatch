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

The host must execute an approved command as the exact argument vector it checked, without passing it through a shell or reinterpreting its arguments. It must also avoid a check/use race for filesystem targets and route every relevant tool path through the same gate. This prototype does not supply that host integration.

The receipt records a deterministic decision about supplied inputs. It is not a cryptographic signature, tamper-proof log, proof of actual execution, or security certification. A SHA-256 digest detects byte changes relative to a previously trusted reference; it does not establish who authored or approved the content.

Version 1 receipts identify a relative file path and the task/session, but do not include the workspace identity. An integrating host must bind its chosen workspace to that task and grant; two different workspaces can otherwise produce the same receipt for the same relative request. A future receipt revision should carry a host-observed workspace identifier if cross-workspace audit comparison is needed.

## Integration direction

An integration should call SkillLatch at a real tool boundary, identify the active instruction artifacts as host-observed context, include the tool identity and version, and retain the resulting decision. It should never infer that a skill caused a call solely because its text was loaded. For MCP-served skills, preserve server identity and URI, and follow the existing [MCP Skills security requirements](https://modelcontextprotocol.io/extensions/skills/overview). Explore interceptor hooks with the [MCP Interceptors Working Group](https://modelcontextprotocol.io/community/working-groups/interceptors) before proposing new wire fields.
