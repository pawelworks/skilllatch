# SkillLatch: early foundation discussion brief

**Status:** Local proof of concept under development. No AAIF proposal has been submitted for SkillLatch. No endorsement, adoption, security certification, or asset transfer is claimed.

## Problem

Agent skills are instruction packages that may guide a host to call tools. A pre-install scan can identify suspicious text or code, but a host still needs to decide whether each later file, network, or command request fits the user's task-specific permission. A general permission to load a skill does not by itself describe the least privilege needed for one action.

## Proposed contribution

SkillLatch tests a small, vendor-neutral contract for action-level permission decisions: a content-bound skill identity, declared capability ceiling, task/session grant, normalized action request, deterministic allow/deny result, and reviewable receipt. The current code is a decision library and CLI. A real host or interceptor must enforce it at the tool boundary.

A first implementation of the context provenance envelope now exists (skilllatch.context.v1, [skilllatch/context.py](../skilllatch/context.py)): local skill digests or MCP server identity and URI, project-instruction digests, tool identity and schema digest, advisory identity, and the grant hash, with attribution fixed to `unknown`; no causality is claimed. It is meant to be designed with existing MCP groups, not presented as a competing standard. An illustrative validator-style interceptor example ([examples/mcp_interceptor.py](../examples/mcp_interceptor.py)), informed by the draft Interceptors proposal SEP-2624 but not an implementation of it, accompanies the reference gated host.

## Relationship to other projects

- [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) performs pre-install skill security analysis (Apache-2.0, currently v2.12.0) with static plus optional LLM stages and JSON/SARIF output. An offline advisory loader for its JSON report shape is now included (`load_scan_report`); no scanner integration is claimed.
- The [MCP Skills extension](https://modelcontextprotocol.io/extensions/skills/overview) already defines digest verification, origin tracking, and content-bound host approval. SkillLatch should reuse those identities and approval rules when an adapter exists.
- The [MCP Security Interest Group](https://modelcontextprotocol.io/community/interest-groups/security) identifies runtime drift and auditability as active topics. The [Interceptors Working Group](https://modelcontextprotocol.io/community/working-groups/interceptors) is relevant to any host-side hook.

## Evidence needed before a foundation submission

1. A reviewed threat model and falsifiable negative fixtures, including hidden instruction, unexpected file access, unapproved egress, command changes, symlink escapes, and stale grants.
2. An in-repo reference adapter demonstrates that denied requests never reach a tool (simulated tools); production-host integration and independent reproduction remain open; the interceptor example uses simulated tools and is not live protection evidence either.
3. Cross-vendor feedback and permissioned pilot results. Initial examples are simulations, not live protection evidence.
4. Contribution rights, maintainer governance, project-asset inventory, and explicit authority for any foundation form's legal commitments.

The initial conversation with AAIF or MCP groups should ask whether an action-level evidence profile or reference adapter would fit an existing workstream. It should not claim a new standard or a gap that other projects do not have.
