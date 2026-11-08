FROM python:3.13-slim
RUN pip install --no-cache-dir "mcp==1.30.0"
WORKDIR /opt/harness
COPY findings_db.py ops.py findings.py worker.py intel.py redact.py web.py webfetch.py ./
EXPOSE 8091 8092 8093 8094
CMD ["python3", "worker.py"]
