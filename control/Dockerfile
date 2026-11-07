FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY lineage_core ./lineage_core
COPY control ./control
COPY policy ./policy
COPY fixtures/errortrack_issues.json ./fixtures/errortrack_issues.json
RUN pip install --no-cache-dir .
ENV LINEAGE_POLICY_PATH=/app/policy/default.yaml \
    LINEAGE_LOCAL_SECRETS_PATH=/app/.lineage/secrets.yaml \
    PYTHONUNBUFFERED=1
EXPOSE 8000 8001 8002
CMD ["python", "-m", "control.main"]
