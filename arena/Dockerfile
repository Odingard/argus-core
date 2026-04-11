FROM python:3.11-slim

WORKDIR /app

# Install only what Arena scenarios need
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic

# Copy arena package
COPY arena/ /app/arena/

# Default — overridden by docker-compose per scenario
ENV ARENA_SCENARIO="arena-01-prompt-leak"
ENV ARENA_PORT="9001"

EXPOSE ${ARENA_PORT}

# Each scenario module has a create_app() factory + __main__ block.
# The entrypoint is set per-service in docker-compose.yml.
CMD ["python", "-m", "arena.runner"]
