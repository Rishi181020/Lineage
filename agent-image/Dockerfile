FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git nodejs npm \
 && rm -rf /var/lib/apt/lists/*
# onFailure: "block" in the managed hooks needs v2.1.295 or later.
RUN npm install -g @anthropic-ai/claude-code@2.1.319 \
 && pip install --no-cache-dir "mcp>=1.2,<2"
COPY lineage-hook /usr/local/bin/lineage-hook
COPY lineage-agent /usr/local/bin/lineage-agent
COPY managed-settings.json /etc/claude-code/managed-settings.json
COPY mcp.json errortrack_mcp.py /etc/lineage/
COPY --from=fixtures errortrack_issues.json /etc/lineage/errortrack_issues.json
RUN chmod 0755 /usr/local/bin/lineage-hook /usr/local/bin/lineage-agent \
 && chmod 0644 /etc/claude-code/managed-settings.json \
 && useradd --create-home agent \
 && mkdir -p /workspace \
 && chown agent /workspace
ENV HTTP_PROXY=http://egress:8080 \
    HTTPS_PROXY=http://egress:8080 \
    NO_PROXY=control,modeltap \
    http_proxy=http://egress:8080 \
    https_proxy=http://egress:8080 \
    no_proxy=control,modeltap \
    NPM_CONFIG_REGISTRY=http://registry.demo/
# Non-root, because Claude Code refuses to bypass its own permission prompts as root.
USER agent
WORKDIR /workspace
CMD ["sleep", "infinity"]
