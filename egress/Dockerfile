FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY lineage_core ./lineage_core
COPY egress/addon.py ./addon.py
COPY policy ./policy
RUN pip install --no-cache-dir . httpx pyyaml
ENV LINEAGE_POLICY_PATH=/app/policy/default.yaml \
    LINEAGE_LOCAL_SECRETS_PATH=/app/.lineage/secrets.yaml \
    PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "addon.py"]
