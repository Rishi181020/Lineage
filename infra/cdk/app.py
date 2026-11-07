#!/usr/bin/env python3
import aws_cdk as cdk

from lineage_stack import LineageStack

app = cdk.App()
LineageStack(
    app,
    "LineageStack",
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region") or "us-west-2",
    ),
)
app.synth()
