# ── ARGUS Runtime Container ─────────────────────────────────────────────────
# Pins Python 3.12 + Node 22 so macOS updates, nvm switches, and Homebrew
# version bumps cannot break the engagement runtime. Docker socket is
# mounted at run-time so ARGUS can spin up target containers (node-code-
# sandbox-mcp, etc.) on the host Docker daemon — same as running natively.
#
# Build:  docker build -t argus:latest .
# Run:    docker run --rm -it \
#           -v /var/run/docker.sock:/var/run/docker.sock \
#           -v $(pwd):/app \
#           --env-file .env \
#           argus:latest \
#           argus engage "npx://-y node-code-sandbox-mcp@1.2.0" --output /tmp/out

FROM python:3.12-slim

# ── System deps ──────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Node 22 (pinned) ─────────────────────────────────────────────────────────
ENV NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y nodejs \
    && node --version \
    && npm --version \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps ──────────────────────────────────────────────────────────────
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[webhook]" 2>/dev/null || \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir mcp anthropic openai google-generativeai \
    pydantic python-dotenv networkx docker pyyaml requests

# ── ARGUS source ─────────────────────────────────────────────────────────────
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# ── Entrypoint ───────────────────────────────────────────────────────────────
ENTRYPOINT ["argus"]
CMD ["--help"]
