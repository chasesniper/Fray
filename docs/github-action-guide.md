# Fray GitHub Action — CI/CD Security Testing

Run Fray WAF security tests automatically in your CI/CD pipeline. Detects WAF vendors, tests 4,000+ payloads for bypasses, and posts results as PR comments.

## Quick Start

```yaml
# .github/workflows/waf-test.yml
name: WAF Security Test
on:
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  fray:
    runs-on: ubuntu-latest
    steps:
      - uses: dalisecurity/fray@v3
        with:
          target: 'https://staging.example.com'
```

That's it — Fray will detect the WAF, run smart payload selection, and comment results on the PR.

## Full Example

```yaml
name: WAF Security Test
on:
  pull_request:
    branches: [main]
  workflow_dispatch:
    inputs:
      target:
        description: 'Target URL'
        required: true

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - name: Fray WAF Test
        id: fray
        uses: dalisecurity/fray@v3
        with:
          target: ${{ github.event.inputs.target || 'https://staging.example.com' }}
          mode: smart
          max-payloads: '100'
          stealth: 'true'
          delay: '0.5'
          fail-on-bypass: 'true'
          comment-on-pr: 'true'
          output-file: 'fray-results.json'

      - name: Check results
        run: |
          echo "Total: ${{ steps.fray.outputs.total }}"
          echo "Blocked: ${{ steps.fray.outputs.blocked }}"
          echo "Bypassed: ${{ steps.fray.outputs.bypassed }}"
          echo "Block Rate: ${{ steps.fray.outputs.block-rate }}"
          echo "WAF: ${{ steps.fray.outputs.waf-vendor }}"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target` | **Yes** | — | Target URL (e.g. `https://example.com`) |
| `mode` | No | `smart` | `smart` (recommended), `all`, or a category name |
| `category` | No | `""` | Override category: `xss`, `sqli`, `ssrf`, `rce`, etc. |
| `max-payloads` | No | `50` | Max payloads per category |
| `stealth` | No | `false` | UA rotation, jitter, throttle |
| `delay` | No | `0.5` | Delay between requests (seconds) |
| `fail-on-bypass` | No | `false` | Fail the workflow if any bypass is found |
| `comment-on-pr` | No | `true` | Post results as a PR comment |
| `cookie` | No | `""` | Cookie header for authenticated scanning |
| `bearer` | No | `""` | Bearer token for authenticated scanning |
| `scope-file` | No | `""` | Path to scope file for target validation |
| `webhook` | No | `""` | Slack/Discord/Teams webhook for notifications |
| `output-file` | No | `fray-results.json` | JSON results file path |
| `python-version` | No | `3.12` | Python version |
| `fray-version` | No | `""` | Specific Fray version (blank = latest) |

## Outputs

| Output | Description |
|--------|-------------|
| `total` | Total payloads tested |
| `blocked` | Payloads blocked by WAF |
| `bypassed` | Payloads that bypassed WAF |
| `block-rate` | Block rate percentage |
| `waf-vendor` | Detected WAF vendor |
| `results-file` | Path to JSON results |

## Use Cases

### 1. Block PRs with WAF bypasses

```yaml
- uses: dalisecurity/fray@v3
  with:
    target: 'https://staging.example.com'
    fail-on-bypass: 'true'
```

### 2. Authenticated scanning

```yaml
- uses: dalisecurity/fray@v3
  with:
    target: 'https://app.example.com/api'
    bearer: ${{ secrets.API_TOKEN }}
```

### 3. Specific category test

```yaml
- uses: dalisecurity/fray@v3
  with:
    target: 'https://example.com'
    category: 'sqli'
    max-payloads: '200'
```

### 4. Slack notifications on bypass

```yaml
- uses: dalisecurity/fray@v3
  with:
    target: 'https://example.com'
    webhook: ${{ secrets.SLACK_WEBHOOK }}
```

### 5. Scheduled weekly security scan

```yaml
on:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  weekly-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: dalisecurity/fray@v3
        with:
          target: 'https://example.com'
          mode: 'all'
          max-payloads: '500'
```

### 6. Multi-target matrix

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - https://api.example.com
          - https://app.example.com
          - https://admin.example.com
    steps:
      - uses: dalisecurity/fray@v3
        with:
          target: ${{ matrix.target }}
          fail-on-bypass: 'true'
```

## PR Comment

When `comment-on-pr` is `true`, Fray posts a results summary:

| Metric | Value |
|--------|-------|
| Target | `https://example.com` |
| WAF Detected | Cloudflare |
| Total Payloads | 100 |
| Blocked | 97 |
| Bypassed | 3 |
| Block Rate | 97.0% |

## Artifacts

Results are automatically uploaded as a `fray-results` artifact (retained 30 days). Download from the Actions tab.

## Publishing to GitHub Actions Marketplace

The action is available at:
- **Repository:** `dalisecurity/fray`
- **Usage:** `uses: dalisecurity/fray@v3`
- **Marketplace:** [github.com/marketplace/actions/fray-waf-security-test](https://github.com/marketplace/actions/fray-waf-security-test)
