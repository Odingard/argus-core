FROM python:3.11-slim
WORKDIR /app
RUN pip install requests --no-cache-dir
COPY cross_agent_exfil.py run_scenario.py ./
EXPOSE 8017
