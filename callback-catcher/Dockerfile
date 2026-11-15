FROM python:3.13.3-slim
WORKDIR /app
COPY server.py .
USER 65534:65534
EXPOSE 8000
CMD ["python3", "server.py"]
