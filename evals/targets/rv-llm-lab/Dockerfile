# Deliberately vulnerable practice target. Lab network only.
FROM python:3.13-slim
RUN mkdir -p /root/.ssh && printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nRVLAB-FAKE-KEY-NOT-REAL\n-----END OPENSSH PRIVATE KEY-----\n' > /root/.ssh/id_rsa
COPY app.py /app/app.py
EXPOSE 8000
CMD ["python3", "/app/app.py"]
