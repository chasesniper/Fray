# AGENTS.md — Coding Agent Guidelines for Fray

This file provides context for AI coding agents (Claude Code, Cursor, Copilot, etc.) working on the Fray codebase.

## Project Overview

Fray is an open-source WAF bypass and security testing toolkit. It combines reconnaissance, scanning, bypass, and hardening into a single CLI tool with zero external dependencies (pure Python stdlib).

**Repository:** [github.com/dalisecurity/fray](https://github.com/dalisecurity/fray)
**Package:** [pypi.org/project/fray](https://pypi.org/project/fray/)

## Architecture

```
fray/
├── __init__.py          # Package init, DATA_DIR, load helpers
├── __main__.py          # CLI entry point (argparse)
├── tester.py            # Core payload testing engine
├── scanner.py           # Auto-crawl + injection scanner
├── bypass.py            # 5-phase WAF evasion scorer
├── ai_bypass.py         # AI-assisted adaptive bypass (LLM + local)
├── harden.py            # OWASP hardening audit (A-F grade)
├── detector.py          # WAF vendor fingerprinting (25 vendors)
├── mutation.py          # 20-strategy payload mutation engine
├── reporter.py          # HTML/Markdown/SARIF report generation
├── mcp_server.py        # MCP server (14 tools for AI agents)
├── recon/
│   ├── pipeline.py      # 27-check recon orchestrator
│   ├── checks.py        # Individual recon check implementations
│   └── ...
├── data/
│   ├── payloads/        # 6,300+ payloads in JSON (24 categories)
│   ├── waf_signatures/  # WAF detection fingerprints
│   └── waf_intel.json   # Per-vendor bypass strategies
└── docs/                # 30+ documentation guides
```

## Key Design Principles

1. **Zero dependencies** — Only Python stdlib. No `requests`, no `aiohttp`, no third-party packages. Use `urllib.request`, `http.client`, `ssl`, `json`, `concurrent.futures`.
2. **Single pip install** — Everything ships in the package. Payloads are bundled in `fray/data/`.
3. **CLI-first** — All features accessible via `fray <command>`. No web UI required.
4. **Defensive coding** — Every network call must handle timeouts, connection errors, and rate limiting (429 backoff).
5. **Scope enforcement** — Never send requests to hosts outside `--scope`. Check before every request.

## Development Commands

```bash
# Install in dev mode
pip install -e '.[dev]'

# Run tests
pytest tests/ -v

# Run a specific test
pytest tests/test_tester.py -v

# Type checking
mypy fray/ --ignore-missing-imports

# Lint
ruff check fray/

# Build package
python -m build
```

## Common Tasks

### Adding a new payload category
1. Create `fray/data/payloads/<category>.json` following the existing schema
2. Add category to `CATEGORIES` in `fray/__init__.py`
3. Update `fray/data/payloads/metadata.json` with count

### Adding a new WAF signature
1. Add fingerprint to `fray/data/waf_signatures/`
2. Update `detector.py` with detection logic
3. Add vendor to `waf_intel.json` if bypass strategies are known

### Adding a new recon check
1. Implement in `fray/recon/checks.py`
2. Register in `fray/recon/pipeline.py`
3. Update the check count in docs if total changes

### Adding a new MCP tool
1. Add handler in `fray/mcp_server.py`
2. Register tool schema with name, description, and input schema
3. Update tool count in README if total changes

## Code Style

- Python 3.8+ compatible (no walrus operator in hot paths, use `typing` for type hints)
- PEP 8 with 120-char line length
- Docstrings for public functions (Google style)
- Use `logging` module, not `print()` for debug output
- CLI output uses `print()` with color via ANSI codes (helper in `fray/utils.py`)

## Testing

- Tests in `tests/` mirror the `fray/` structure
- Use `pytest` fixtures for common setup (mock HTTP responses)
- Network calls in tests must be mocked — no real HTTP requests in CI
- Payload validation tests ensure all JSON files parse correctly

## Important Constraints

- **Never add external dependencies** to the core package. Optional extras (like `fray[mcp]`) may use `mcp` package.
- **Never remove payloads** — only add or recategorize.
- **Never weaken security checks** in `harden.py` without explicit direction.
- **Always preserve backward compatibility** in CLI arguments and JSON output schema.
- **Authorized testing only** — all docs and examples must use `example.com` or explicitly mention authorization requirements.

## Commit Convention

```
feat: Add 50 new SVG-based XSS payloads
fix: Correct classification of polyglot payloads
docs: Update methodology documentation
refactor: Improve payload classifier performance
test: Add unit tests for analyzer tool
chore: Maintenance tasks
```

## Contact

- **Security issues:** soc@dalisec.io
- **General questions:** [GitHub Discussions](https://github.com/dalisecurity/fray/discussions)
