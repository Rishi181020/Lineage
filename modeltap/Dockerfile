FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY lineage_core ./lineage_core
COPY modeltap ./modeltap
RUN pip install --no-cache-dir . httpx boto3 botocore fastapi uvicorn PyJWT
ENV PYTHONUNBUFFERED=1
EXPOSE 8100
CMD ["uvicorn", "modeltap.app:app", "--host", "0.0.0.0", "--port", "8100"]
