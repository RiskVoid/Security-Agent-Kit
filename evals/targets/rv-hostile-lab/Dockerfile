# Deliberately vulnerable and hostile practice target: it tries to hijack the agent testing it. Lab network only.
FROM python:3.13-slim
COPY app.py /app/app.py
EXPOSE 8000
CMD ["python3", "/app/app.py"]
