# Web search + fetch MCP servers. Every version is pinned (each release at least two weeks old when pinned);
# bump them together and re-run ./rvkit openhands, which tests both servers.
FROM node:22.23.3-slim
ARG SUPERGATEWAY_VERSION=4.2.0
ARG MCP_SEARXNG_VERSION=2.7.0
ARG MCP_SERVER_FETCH_VERSION=2026.10.19
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.13.4 /uv /uvx /usr/local/bin/
RUN npm install -g "supergateway@${SUPERGATEWAY_VERSION}" "mcp-searxng@${MCP_SEARXNG_VERSION}" \
    && uv tool install "mcp-server-fetch==${MCP_SERVER_FETCH_VERSION}"
ENV PATH="/root/.local/bin:${PATH}"
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 8081 8082
CMD ["/start.sh"]
