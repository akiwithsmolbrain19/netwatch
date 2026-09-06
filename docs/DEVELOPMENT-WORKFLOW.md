# Development workflow — NetWatch

```
Requirement
    ↓
AI design proposal
    ↓
Human review
    ↓
AI implementation
    ↓
Automated tests          python3 -m pytest tests/ -q (32 tests)
    ↓
Static analysis          python3 -m py_compile $(git ls-files '*.py')
    ↓
Security scanning        secret scan (see Makefile `security`)
    ↓
Adversarial review       docs/DETECTION-REVIEW.md checklist
    ↓
Human git diff review    git status / git diff
    ↓
Commit (human only)
```

## Rules
- The human accepts or rejects every change. The AI is an assistant, not an authority.
- "Tests passed" is never sufficient alone: also require static analysis, security
  scan, adversarial review, and a human-read `git diff`.
- No auto-commit. No history rewrites. No fake commits.
- Commit granularity: one focused change per commit (e.g. "one NW-1xx rule + its tests").
- Tooling note (2026-09-06): this environment is offline with no pip; pytest/ruff/bandit
  are unavailable. Tests are pytest-style and cannot run here until pytest is installed.
  The Makefile `test` target tries pytest and reports clearly. If ruff/bandit are installed
  later, prefer `ruff check .` and `bandit -r .` with narrow suppressions, recorded in DECISIONS.md.

## Change verification (per change)
1. What changed. 2. Why. 3. Security implications. 4. Failure modes.
5. Tests validating it. 6. Test run. 7. Lint/security run. 8. `git diff` shown.
