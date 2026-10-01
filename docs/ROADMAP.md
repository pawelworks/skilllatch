# Roadmap

This is a proposed sequence, not funded work or a promise of adoption.

## First four weeks

- Make the local policy contract small and testable: strict JSON parsing, skill byte inventory, declared capability ceiling, short-lived grant, deterministic decision and receipt.
- ~~Publish inert negative examples for unexpected file access, unapproved egress, changed commands, stale grants, and path escapes.~~ **Completed:** superseded by the data-driven [conformance fixture suite](../conformance/README.md), which covers every engine reason code and runs in CI.
- Invite technical review of the threat model and model-host trust assumptions.

## Two to three months

- ~~Build one real host adapter that checks a tool request before dispatch and demonstrates a denied request never reaches the tool.~~ **Completed:** [examples/host_adapter.py](../examples/host_adapter.py) is the reference adapter and [examples/demo.py](../examples/demo.py) the scripted demo; its tests prove denied requests never dispatch. Tools are simulated, so production-host integration remains open.
- **Partially completed:** accept advisory scanner evidence from an existing scanner. An offline advisory loader for SkillSpector-shaped JSON reports (`load_scan_report`) is included; a versioned field mapping validated against real SkillSpector output is still open, and no detection rules are reimplemented.
- Explore a context and authority receipt with the MCP Skills and Interceptors working groups. Keep skill origin and server identity explicit; record active instructions without assuming causal attribution. **First increment landed:** version 2 receipts carry the host-observed `workspace_id` and its binding state, and version 2 grants may pin a workspace identity.

## Four to six months

- Run a permissioned cross-host evaluation with published positive and negative fixtures, failure cases, overhead, and bypass limits.
- Seek maintainers outside the founding company and decide whether the work belongs upstream in an existing project, as a shared profile, or as a separate foundation candidate.
- Prepare any foundation proposal only with documented contributor rights, governance, asset scope, and evidence from actual users or adapters.
