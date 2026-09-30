# Draft: request for technical feedback, not an AAIF project application

**Subject:** SkillLatch: task-scoped action decisions for agent skills

Hello AAIF and MCP contributors,

We are prototyping SkillLatch, a small open-source policy decision component for AI agent skills. A host provides the approved skill snapshot, a declared capability ceiling, a short-lived grant for one task/session, and a proposed tool action. SkillLatch returns a deterministic allow/deny decision and a reviewable receipt. The host must call it before dispatch and enforce the result.

This work was prompted by demonstrations of malicious skill instructions, including NVIDIA SkillSpector's pre-install scanning examples. We intend to complement existing scanners, not duplicate their detection rules. The MCP Skills extension already defines skill origin, digests, and content-bound approval; SkillLatch explores the additional action-level authority question and how to record the decision consistently across hosts.

We would value feedback on whether a small reference adapter and context/authority receipt would fit current MCP Skills, Security Interest Group, or Interceptors Working Group work. In particular: which tool identity and grant facts can a host reliably assert, and which should remain explicitly unknown? We will avoid treating a loaded skill as proof that it caused a tool call.

The first implementation is a local CLI and test fixtures. It has not been integrated into a production host or independently audited. No foundation status or adoption is claimed. We would welcome review of the threat model and the most useful first host integration.

Maintainer: Pavel Mihai Lucian, PAWELWORKS S.R.L.
Contact: lucian.pavel@pawelworks.com

Repository: https://github.com/pawelworks/skilllatch

---

Publish this only after the repository and examples are verified, and adapt the wording to the specific working group's discussion venue. A separate AAIF project proposal would require its own eligibility evidence and owner authorization for that project's legal and asset commitments.
