FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY lineage-hook /usr/local/bin/lineage-hook
COPY managed-settings.json /etc/claude-code/managed-settings.json
RUN chmod 0755 /usr/local/bin/lineage-hook \
 && chmod 0644 /etc/claude-code/managed-settings.json \
 && mkdir -p /etc/lineage
ENV HTTP_PROXY=http://egress:8080 \
    HTTPS_PROXY=http://egress:8080 \
    NO_PROXY=control,modeltap \
    NPM_CONFIG_REGISTRY=http://registry.demo/
WORKDIR /workspace
CMD ["sleep", "infinity"]
