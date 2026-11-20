# A small OAuth2 authorization server with seeded flaws (the lab case of the OAuth playbook). Lab network only.
# FIXED=1 (a compose build arg on lab-oauth-fixed) is baked into the image's environment: the app reads it at
# runtime to implement the flows correctly (the clean controls).
FROM python:3.13-slim
ARG FIXED
ENV FIXED=${FIXED}
COPY app.py /app/app.py
EXPOSE 8000
CMD ["python3", "/app/app.py"]
