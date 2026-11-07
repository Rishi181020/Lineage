#!/usr/bin/env python3
"""Create demo secrets locally or in AWS Secrets Manager."""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

DEMO_STAGING = "lineage_demo_real_staging_token"


def seed_local(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    operator = secrets.token_urlsafe(24)
    service = secrets.token_urlsafe(24)
    (root / "operator-token").write_text(operator, encoding="utf-8")
    (root / "service-token").write_text(service, encoding="utf-8")
    secrets_yaml = root / "secrets.yaml"
    secrets_yaml.write_text(
        "\n".join(
            [
                f"lineage/custody/staging-infra: {DEMO_STAGING}",
                f"lineage/operator-token: {operator}",
                f"lineage/service-token: {service}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"Wrote local secrets under {root}")
    print(f"operator token: {operator}")
    print(f"service token: {service}")
    print(f"staging real token: {DEMO_STAGING}")


def seed_aws(region: str) -> None:
    import boto3

    client = boto3.client("secretsmanager", region_name=region)
    values = {
        "lineage/operator-token": secrets.token_urlsafe(24),
        "lineage/service-token": secrets.token_urlsafe(24),
        "lineage/custody/staging-infra": DEMO_STAGING,
    }
    for name, value in values.items():
        try:
            client.create_secret(Name=name, SecretString=value)
            print(f"created {name}")
        except client.exceptions.ResourceExistsException:
            client.put_secret_value(SecretId=name, SecretString=value)
            print(f"updated {name}")
    print(json.dumps({k: ("***" if "custody" in k else v) for k, v in values.items()}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["local", "aws"], default="local")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--path", default=".lineage")
    args = parser.parse_args()
    if args.mode == "local":
        seed_local(Path(args.path))
    else:
        seed_aws(args.region)


if __name__ == "__main__":
    main()
