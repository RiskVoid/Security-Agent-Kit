FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN npm install -g supergateway mcp-searxng && uv tool install mcp-server-fetch
ENV PATH="/root/.local/bin:${PATH}"
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 8081 8082
CMD ["/start.sh"]
