# LLM Context Discovery

This project keeps its contributor context in plain files that people and
LLM coding assistants read alike.

## Context Files

| File | Purpose | Consumers |
|------|---------|-----------|
| `AGENTS.md` | Primary contributor/agent context | People and LLM tools |
| `CONVENTIONS.md` | Code style and build rules | People and LLM tools |
| `FUNCTION_MANIFEST.md` + per-directory `FUNCTION_SUBMANIFEST.md` | Generated index of every named function | Search before adding code |
| `specs/*.feature` | BDD behavior specs | People and LLM tools |
| `specs/*.schema` | Type definitions | Generators + LLMs |
| `specs/*.sm` | State machines | Generators + LLMs |

## Tool-specific Symlinks

All point to `AGENTS.md` (single source of truth):

| File | Tool |
|------|------|
| `.claude/CLAUDE.md` | Claude Code |
| `.cursorrules` | Cursor |
| `.github/copilot-instructions.md` | GitHub Copilot |
| `LLM.md` | Generic |
| `CONTEXT.md` | Generic |

```
AGENTS.md  <- canonical source
    ^
    +-- .claude/CLAUDE.md
    +-- .cursorrules
    +-- .github/copilot-instructions.md
    +-- LLM.md
    +-- CONTEXT.md
```

## Discovery Order

1. `AGENTS.md` (preferred)
2. `LLM_CONTEXT.md` (this file)
3. `CONVENTIONS.md`
4. `README.md`
5. Tool-specific files (`.claude/`, `.cursorrules`, ...)
