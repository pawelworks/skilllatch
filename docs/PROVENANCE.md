# Origin and evidence

SkillLatch was started on 1 October 2026 at Pavel Mihai Lucian's request. A short social video about NVIDIA SkillSpector prompted the question of how a host should decide an individual tool action after a skill has already been inspected. The video demonstrated an illustrative `chef-assistant` skill with concealed instructions and a high scanner score. That demonstration is a reference for the problem, not SkillLatch test evidence.

The initial SkillLatch code and text were drafted with AI assistance under the owner's direction. No NVIDIA source code, rules, screenshots, logos, or video assets were copied into this repository. [SkillSpector](https://github.com/NVIDIA/SkillSpector), the [MCP Skills extension](https://modelcontextprotocol.io/extensions/skills/overview), and the [MCP Security Interest Group](https://modelcontextprotocol.io/community/interest-groups/security) are cited for the existing work and scope boundaries.

The example requests are inert fixtures. Passing unit tests establishes only the coded decision behavior for those inputs. It does not prove that any host enforces the result, that an installed skill is safe, or that RelayReady or AAIF has adopted SkillLatch.

The follow-on increment — the reference host adapter, scripted demo, conformance fixtures, version 2 receipts and grants, the offline scan-report adapter, and the fabricated sample report — was likewise drafted with AI assistance under the owner's direction. The sample report and all fixtures are illustrative fabrications shaped like published tool output; no scanner code, rules, or assets were copied.
