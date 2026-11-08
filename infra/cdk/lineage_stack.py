from __future__ import annotations

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from constructs import Construct


class LineageStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        Tags.of(self).add("project", "lineage")

        vpc = ec2.Vpc(
            self,
            "Vpc",
            max_azs=1,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                )
            ],
        )

        sg = ec2.SecurityGroup(
            self,
            "InstanceSg",
            vpc=vpc,
            allow_all_outbound=True,
            description="Lineage host — no inbound",
        )
        # Explicitly no inbound rules (D11).

        runs = dynamodb.Table(
            self,
            "Runs",
            table_name="lineage-runs",
            partition_key=dynamodb.Attribute(
                name="run_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )
        events = dynamodb.Table(
            self,
            "Events",
            table_name="lineage-events",
            partition_key=dynamodb.Attribute(
                name="run_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="ts#seq", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,
        )
        entities = dynamodb.Table(
            self,
            "Entities",
            table_name="lineage-entities",
            partition_key=dynamodb.Attribute(
                name="run_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="entity", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        key = kms.Key(
            self,
            "RunTokenKey",
            key_spec=kms.KeySpec.ECC_NIST_P256,
            key_usage=kms.KeyUsage.SIGN_VERIFY,
            enable_key_rotation=False,
            removal_policy=RemovalPolicy.DESTROY,
        )
        kms.Alias(self, "RunTokenAlias", alias_name="alias/lineage-run-token", target_key=key)

        log_group = logs.LogGroup(
            self,
            "Logs",
            log_group_name="/lineage",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        role = iam.Role(
            self,
            "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                )
            ],
        )
        runs.grant_read_write_data(role)
        events.grant_read_write_data(role)
        entities.grant_read_write_data(role)
        key.grant(role, "kms:Sign", "kms:GetPublicKey")
        role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:lineage/*"
                ],
            )
        )
        role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=["*"],
            )
        )
        log_group.grant_write(role)

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "dnf update -y || yum update -y",
            "dnf install -y docker git python3.12 || yum install -y docker git python3",
            "systemctl enable --now docker",
            "mkdir -p /usr/local/lib/docker/cli-plugins",
            "curl -fsSL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 "
            "-o /usr/local/lib/docker/cli-plugins/docker-compose",
            "chmod +x /usr/local/lib/docker/cli-plugins/docker-compose",
            # The agent image build uses additional_contexts, which needs BuildKit via buildx.
            "curl -fsSL https://github.com/docker/buildx/releases/download/v0.17.1/buildx-v0.17.1.linux-amd64 "
            "-o /usr/local/lib/docker/cli-plugins/docker-buildx",
            "chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx",
            "curl -LsSf https://astral.sh/uv/install.sh | sh",
            "usermod -aG docker ssm-user || true",
            "echo 'Lineage host bootstrap complete' > /var/log/lineage-bootstrap.txt",
        )

        instance = ec2.Instance(
            self,
            "Host",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3, ec2.InstanceSize.LARGE
            ),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            security_group=sg,
            role=role,
            user_data=user_data,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(40, volume_type=ec2.EbsDeviceVolumeType.GP3),
                )
            ],
            require_imdsv2=True,
        )
        # Hop limit 2 so containers can use the instance role (D14).
        instance.instance.add_property_override(
            "MetadataOptions.HttpPutResponseHopLimit", 2
        )

        CfnOutput(self, "InstanceId", value=instance.instance_id)
        CfnOutput(self, "Region", value=self.region)
        CfnOutput(self, "RunsTable", value=runs.table_name)
        CfnOutput(self, "EventsTable", value=events.table_name)
        CfnOutput(self, "EntitiesTable", value=entities.table_name)
        CfnOutput(self, "KmsKeyArn", value=key.key_arn)
        CfnOutput(self, "LogGroup", value=log_group.log_group_name)
