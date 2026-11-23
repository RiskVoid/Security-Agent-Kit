FROM python:3.13-alpine
WORKDIR /app
COPY app.py identities.json identities-admin.json ./
RUN cp identities.json identities-active.json
EXPOSE 8000
CMD ["python3", "app.py"]
