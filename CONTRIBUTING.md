# Contributing to SkillLatch

The first release is a narrow experiment. Please open an issue before changing its policy semantics or claiming compatibility with a host. A change to the decision format should include an example and a negative test. Keep optional host adapters separate from the dependency-free core.

Development uses Python 3.11 or newer:

```console
python -m unittest discover -s tests -v
```

Do not run untrusted skill code in a test or submit real credentials, private files, or unredacted tool traces. Simulated malicious examples must use inert endpoints and fixture data. Report security problems privately as described in [SECURITY.md](SECURITY.md).

Contributions are reviewed by the maintainer under [GOVERNANCE.md](GOVERNANCE.md). Do not state that a contribution or scanner result has received independent validation unless the review record supports it.
