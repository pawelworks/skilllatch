# Conformance fixtures

Data-driven allow/deny cases for the SkillLatch decision engine. Each file is
one case, executed by `tests/test_conformance.py`. The fixtures are inert:
they describe temporary file trees and JSON inputs, never real skills.

## Decision-case schema

```json
{
  "name": "01-allow-read-file",
  "description": "human-readable purpose",
  "setup": {
    "skill_files": {"SKILL.md": "content"},
    "workspace_files": {"recipes/soup.txt": "content"}
  },
  "manifest": {"version": 1, "...": "..."},
  "grant": {"version": 2, "...": "..."},
  "request": {"session_id": "...", "task_id": "...", "kind": "file", "...": "..."},
  "at": "2026-10-01T12:00:00Z",
  "workspace_id": "conf-ws",
  "expect": {"allowed": true, "reason_code": "allowed"}
}
```

- `setup.skill_files` / `setup.workspace_files`: mapping of relative path to
  UTF-8 file content, materialized into a fresh temporary directory per case.
  `skill_files: null` leaves the skill directory absent (invalid tree).
  `workspace_files: null` creates the workspace path as a regular file instead
  of a directory, exercising `invalid_workspace` without needing symlinks.
- The literal string `__SKILL_DIGEST__` anywhere in `manifest` or `grant` is
  recursively replaced with the computed `hash_skill_tree` of the staged skill.
- `at` is an RFC3339 UTC timestamp; `workspace_id` is the host-observed
  workspace identity passed to `evaluate` (use `null` to omit it).
- `expect.workspace_binding`, when present, is also asserted on the receipt.

The runner evaluates each case twice, requires byte-identical receipts, and
recomputes the receipt digest over the canonical receipt minus its `digest`
field before comparing outcomes with `expect`.

## Parse-case schema

```json
{
  "name": "23-parse-duplicate-key",
  "description": "human-readable purpose",
  "parse_check": {"content": "{\"version\": 1, \"version\": 2}",
                  "expect_reason_code": "duplicate_json_key"}
}
```

`content` is written to a temporary file and `load_json_file` must raise
`PolicyError` with `expect_reason_code`.

## Coverage note

Every engine reason code is covered here except `unsafe_file_path`, which is
covered by unit tests only: it requires symlinks or hard links whose creation
needs OS privileges that a JSON fixture cannot portably stage.
