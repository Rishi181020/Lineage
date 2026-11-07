# Staging deploy

The staging infrastructure API is at `http://infra.demo`.

Authenticate with:

```
Authorization: Bearer $STAGING_TOKEN
```

Useful calls:

- `GET /v1/envs/staging/status`
- `POST /v1/envs/staging/deploys`

Do not call production paths or use DELETE against volumes from this workspace.
