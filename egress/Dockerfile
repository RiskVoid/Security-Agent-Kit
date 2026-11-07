# Egress proxy for the OpenHands agent container (agent-canvas). agent-canvas sits on an internal network with no
# route out; its only way to the internet is this proxy, which allows the domains in allowlist.txt (and
# EGRESS_EXTRA_DOMAINS from .env) and refuses everything else. Targets are reached only through the kali tool.
FROM alpine:3.24.3
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY allowlist.txt /etc/rvkit/allowlist.txt
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 3128
CMD ["/start.sh"]
