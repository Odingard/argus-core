FROM python:3.11-slim
WORKDIR /app
RUN pip install requests --no-cache-dir
COPY mcp_server.py target_agent.py run_scenario.py ./
EXPOSE 8001 8002
