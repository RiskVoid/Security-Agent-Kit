#!/bin/sh
# Wrap stdio MCP servers as SSE endpoints (the pattern OpenHands recommends).
#   http://mcp-gateway:8081/sse  -> web search via local SearXNG
#   http://mcp-gateway:8082/sse  -> fetch any URL as markdown
supergateway --stdio "mcp-searxng" --port 8081 &
supergateway --stdio "mcp-server-fetch" --port 8082 &
wait
