# Docker Usage Guide

Run Fray in a containerized environment for easy portability and CI/CD integration.

## Quick Start

```bash
# Pull and run (from PyPI)
docker build -t fray .
docker run --rm fray recon https://example.com --fast

# Or use docker-compose
docker compose run --rm fray recon https://example.com --fast
```

## Build

```bash
# Production image (installs from PyPI)
docker build -t fray .

# Development image (mounts source code)
docker build --target dev -t fray:dev .
```

## Usage Examples

```bash
# WAF detection
docker run --rm fray detect https://example.com

# Reconnaissance
docker run --rm fray recon https://example.com --fast --json

# Payload testing
docker run --rm fray test https://example.com -c xss --smart

# Full pipeline
docker run --rm fray auto https://example.com

# Save reports to host
docker run --rm -v $(pwd)/reports:/app/reports fray \
  recon https://example.com -o /app/reports/recon.json

# Pipe targets from stdin
cat domains.txt | docker run --rm -i fray recon --fast
```

## Docker Compose

```bash
# Production
docker compose run --rm fray recon https://example.com --fast

# Development (live source mount)
docker compose --profile dev run --rm fray-dev recon https://example.com
```

## Environment Variables

Pass API keys and config via environment:

```bash
docker run --rm \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -e FRAY_TIMEOUT=15 \
  fray ai-bypass https://example.com -c xss
```

Or in `docker-compose.yml`, uncomment the environment lines.

## Persistent Data

Session data, learned patterns, and cache are stored in `/root/.fray` inside the container. Mount a volume to persist across runs:

```bash
docker run --rm \
  -v fray-data:/root/.fray \
  fray agent https://example.com -c xss --rounds 5
```

## CI/CD Integration

```yaml
# .github/workflows/waf-test.yml
name: WAF Security Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Fray
        run: docker build -t fray .
      - name: Run recon
        run: docker run --rm fray recon ${{ secrets.TEST_TARGET }} --fast --json
      - name: Run payload test
        run: |
          docker run --rm fray test ${{ secrets.TEST_TARGET }} \
            -c xss --smart --max 50 --json
```

## Multi-Target Batch Testing

```bash
#!/bin/bash
cat targets.txt | docker run --rm -i \
  -v $(pwd)/reports:/app/reports \
  fray recon --fast
```

## Image Details

- **Base Image**: python:3.12-slim
- **Size**: ~180MB
- **Python**: 3.12
- **Dependencies**: rich (only runtime dep)
- **Multi-stage**: `base` (production) / `dev` (development)

## Security Considerations

- Container runs as root by default (use `--user $(id -u):$(id -g)` to override)
- No sensitive data stored in image
- API keys passed via environment variables (never baked into image)
- Network access required for target testing
- Reports saved to mounted volumes
