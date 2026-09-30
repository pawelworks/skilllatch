# SkillLatch: early foundation discussion brief

**Status:** Local proof of concept under development. No AAIF proposal has been submitted for SkillLatch. No endorsement, adoption, security certification, or asset transfer is claimed.

## Problem

Agent skills are instruction packages that may guide a host to call tools. A pre-install scan can identify suspicious text or code, but a host still needs to decide whether each later file, network, or command request fits the user's task-specific permission. A general permission to load a skill does not by itself describe the least privilege needed for one action.

## Proposed contribution

SkillLatch tests a small, vendor-neutral contract for action-level permission decisions: a content-bound skill identity, declared capability ceiling, task/session grant, normalized action request, deterministic allow/deny result, and reviewable receipt. The current code is a decision library and CLI. A real host or interceptor must enforce it at the tool boundary.

The next research increment is a host-originated context provenance envelope that records which instructions were active when a tool was requested, without claiming those instructions caused the request. Candidate fields include local skill digests, MCP server identity and skill URI, applicable project instructions, optional scanner report digest and mode, tool identity/schema digest, and the effective grant. This should be designed with existing MCP groups rather than presented as a competing standard.

## Relationship to other projects

- [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) performs pre-install skill security analysis and already offers CLI, JSON/SARIF, and MCP integrations. SkillLatch may consume a scan result as one advisory input in a future version; no scanner integration is implemented yet.
- The [MCP Skills extension](https://modelcontextprotocol.io/extensions/skills/overview) already defines digest verification, origin tracking, and content-bound host approval. SkillLatch should reuse those identities and approval rules when an adapter exists.
- The [MCP Security Interest Group](https://modelcontextprotocol.io/community/interest-groups/security) identifies runtime drift and auditability as active topics. The [Interceptors Working Group](https://modelcontextprotocol.io/community/working-groups/interceptors) is relevant to any host-side hook.

## Evidence needed before a foundation submission

1. A reviewed threat model and falsifiable negative fixtures, including hidden instruction, unexpected file access, unapproved egress, command changes, symlink escapes, and stale grants.
2. At least one real host integration that demonstrably blocks a denied tool request, with an independent reproduction and clear disclosure of bypasses.
3. Cross-vendor feedback and permissioned pilot results. Initial examples are simulations, not live protection evidence.
4. Contribution rights, maintainer governance, project-asset inventory, and explicit authority for any foundation form's legal commitments.

The initial conversation with AAIF or MCP groups should ask whether an action-level evidence profile or reference adapter would fit an existing workstream. It should not claim a new standard or a gap that other projects do not have.
