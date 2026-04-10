FROM python:3.11-slim
WORKDIR /app
RUN pip install requests --no-cache-dir
COPY model_extraction_agent.py run_scenario.py ./
EXPOSE 8019
