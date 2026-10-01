# Draft: request for technical feedback, not an AAIF project application

**Subject:** SkillLatch: task-scoped action decisions for agent skills

Hello AAIF and MCP contributors,

We are prototyping SkillLatch, a small open-source policy decision component for AI agent skills. A host provides the approved skill snapshot, a declared capability ceiling, a short-lived grant for one task/session, and a proposed tool action. SkillLatch returns a deterministic allow/deny decision and a reviewable receipt. The host must call it before dispatch and enforce the result.

This work was prompted by demonstrations of malicious skill instructions, including NVIDIA SkillSpector's pre-install scanning examples. We intend to complement existing scanners, not duplicate their detection rules. The MCP Skills extension already defines skill origin, digests, and content-bound approval; SkillLatch explores the additional action-level authority question and how to record the decision consistently across hosts.

We would value feedback on whether a small reference adapter and context/authority receipt would fit current MCP Skills, Security Interest Group, or Interceptors Working Group work. In particular: which tool identity and grant facts can a host reliably assert, and which should remain explicitly unknown? We will avoid treating a loaded skill as proof that it caused a tool call.

The first implementation is a local CLI, a reference gated-host example with a scripted terminal demo, a conformance fixture suite, an offline advisory loader for SkillSpector JSON reports, an illustrative validator-style interceptor example for MCP-shaped tools/call messages (informed by the draft Interceptors proposal SEP-2624, but not an implementation of it or of the MCP Skills extension), and a first host-originated context provenance envelope (skilllatch.context.v1) that records which instruction artifacts were active at request time without claiming they caused the request. The MCP Skills extension (SEP-2640) is Final and the Interceptors proposal (SEP-2624) remains a draft; SkillLatch's scoped experiment is the time-boxed task/session grant and the per-action decision receipt. It has not been integrated into a production host or independently audited. No foundation status or adoption is claimed. We would welcome review of the threat model and the most useful first host integration.

Maintainer: Pavel Mihai Lucian, PAWELWORKS S.R.L.
Contact: lucian.pavel@pawelworks.com

Repository: https://github.com/pawelworks/skilllatch

---

Publish this only after the repository and examples are verified, and adapt the wording to the specific working group's discussion venue. A separate AAIF project proposal would require its own eligibility evidence and owner authorization for that project's legal and asset commitments.
