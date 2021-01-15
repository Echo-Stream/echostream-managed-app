#!/usr/bin/env python3.8
import asyncio
import functools
import json
from base64 import b64decode
from datetime import datetime
from hashlib import sha256
from logging import INFO, WARNING, Formatter, getLogger
from os import environ
from re import compile
from secrets import token_hex
from ssl import _create_unverified_context
from time import gmtime
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

import aiorun
from boto3 import client
from cognitoinator import TokenFetcher
from docker import from_env
from docker.types import Healthcheck, LogConfig, Mount
from docker_image.reference import Reference
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from jose import jwt
from watchtower import CloudWatchLogHandler

from .appsync_websockets import AppSyncOIDCAuthorization, AppSyncWebsocketsTransport

for name in [
    "boto",
    "urllib3",
    "s3transfer",
    "boto3",
    "botocore",
    "nose",
    "gql.transport.aiohttp",
    "gql.transport.websockets",
]:
    getLogger(name).setLevel(environ.get("LOG_LEVEL") or WARNING)

utc_now = datetime.utcnow()
formatter = Formatter(
    fmt="[%(levelname)s] %(asctime)s.%(msecs)03dZ %(thread)d %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
formatter.converter = gmtime
handler = CloudWatchLogHandler(
    log_group=environ["LOG_GROUP_NAME"],
    stream_name=f"{utc_now.year}/{utc_now.month:02}/{utc_now.day:02}/{token_hex(16)}",
    send_interval=1,
    create_log_group=False,
)
handler.setFormatter(formatter)
getLogger().handlers = [handler]
getLogger().setLevel(environ.get("LOG_LEVEL") or INFO)
TOKEN_FETCHER = TokenFetcher()
TENANT = None
NODES = {}
DOCKER = from_env()
ECR_PATTERN = compile(
    r"^[0-9]{12}.dkr.ecr.[a-z]{2}[-[a-z]{3,9}]{,2}-[1-3]{1}.amazonaws.com$"
)
ECR = client("ecr")
NODE_ENV_VARS = {
    "APPSYNC_ENDPOINT": environ["APPSYNC_ENDPOINT"],
    "AUDIT_FIREHOSE": environ["AUDIT_FIREHOSE"],
    "COGNITO_APP_ID": environ["COGNITO_APP_ID"],
    "COGNITO_IDENTITY_POOL_ID": environ["COGNITO_IDENTITY_POOL_ID"],
    "COGNITO_PASSWORD": environ["COGNITO_PASSWORD"],
    "COGNITO_USER_POOL_ID": environ["COGNITO_USER_POOL_ID"],
    "COGNITO_USERNAME": environ["COGNITO_USERNAME"],
    "CONTROL_REGION": environ["CONTROL_REGION"],
    "AWS_DEFAULT_REGION": environ["AWS_DEFAULT_REGION"]
}
HEALTHCHECK_TIME_PATTERN = compile(r"^([0-9]+)(ms|s|m|h)$")
HEALTHCHECK_TIME_MULTIPLIERS = {
    "ms": 1000000,
    "s": 1000000 * 1000,
    "m": 1000000 * 1000 * 60,
    "h": 1000000 * 1000 * 60 * 60,
}


async def _run_in_executor(func: Callable) -> Any:
    return await asyncio.get_running_loop().run_in_executor(
        None,
        func,
    )


def convert_healthcheck_time(value: str) -> int:
    if match := HEALTHCHECK_TIME_PATTERN.match(value):
        return int(match[1]) * HEALTHCHECK_TIME_MULTIPLIERS[match[2]]
    else:
        raise ValueError(f"Value {value} is not a healthcheck time string")


async def initialize_app(app: str) -> None:
    # Clean up hanging containers and images, if any
    await asyncio.gather(
        *[
            _run_in_executor(functools.partial(container.remove, force=True))
            for container in DOCKER.containers.list()
        ]
    )
    await _run_in_executor(functools.partial(print, "Done with the killing"))
    await asyncio.gather(
        _run_in_executor(DOCKER.containers.prune),
        _run_in_executor(
            functools.partial(DOCKER.images.prune, filters={"dangling": True})
        ),
    )
    async with Client(
        transport=AIOHTTPTransport(
            url=environ["APPSYNC_ENDPOINT"],
            headers={"Authorization": f"{TOKEN_FETCHER.id_token}"},
        ),
        fetch_schema_from_transport=True,
    ) as client:
        query = gql(
            """
            query getAppConfig($tenant: String!, $name: String!) {
                SearchApps(tenant: $tenant, name: $name) {
                    items {
                        ... on ManagedApp {
                            nodes {
                                hostMounts {
                                    containerPath
                                    hostPath
                                }
                                logGroupName
                                managedNodeType {
                                    dockerConfig {
                                        imageUrl
                                        password
                                        username
                                    }
                                    healthcheck {
                                        test
                                        interval
                                        timeout
                                        retries
                                        start_period
                                    }
                                    volumes
                                }
                                name
                                portMappings {
                                    containerPort
                                    hostPort
                                }
                            }
                        }
                    }
                    lastEvaluatedKey
                }
            }
            """
        )
        app_result = await client.execute(
            query, variable_values={"tenant": TENANT, "name": app}
        )
    if app_result["SearchApps"]["lastEvaluatedKey"]:
        raise Exception(f"More than one configuration found for {app}")
    if not app_result["SearchApps"]["items"]:
        raise Exception(f"No configuration found for {app}")
    await asyncio.gather(
        *[
            start_node(node_config["name"], node_config)
            for node_config in app_result["SearchApps"]["items"][0]["nodes"]
        ]
    )


async def stop_node(node: str) -> None:
    if container := NODES.get(node, {}).get("container"):
        getLogger().info("Stopping node {node}")
        try:
            # Stop the container
            await _run_in_executor(
                functools.partial(container.stop, timeout=30),
            )
            # Wait for the container to actually stop
            await _run_in_executor(
                functools.partial(container.wait, timeout=30),
            )
            # Remove the container, forcibly if necessary
            await _run_in_executor(
                functools.partial(container.remove, force=True),
            )
            # Remove the tracked reference to the container
            del NODES[node]["container"]
        except asyncio.CancelledError:
            raise
        except Exception:
            getLogger().exception(f"Error occurred stopping {node}")


async def start_node(node: str, node_config: Optional[Dict[str, Any]] = None) -> None:
    await stop_node(node)
    getLogger().info(f"Starting node {node}")
    try:
        if not node_config:
            async with Client(
                transport=AIOHTTPTransport(
                    url=environ["APPSYNC_ENDPOINT"],
                    headers={"Authorization": f"{TOKEN_FETCHER.id_token}"},
                ),
                fetch_schema_from_transport=True,
            ) as client:
                query = gql(
                    """
                    query getNodeConfig($tenant: String!, $name: String!) {
                        SearchNodes(tenant: $tenant, name: $name) {
                            items {
                                ... on ManagedNode {
                                    hostMounts {
                                        containerPath
                                        hostPath
                                    }
                                    logGroupName
                                    managedNodeType {
                                        dockerConfig {
                                            imageUrl
                                            password
                                            username
                                        }
                                        healthcheck {
                                            test
                                            interval
                                            timeout
                                            retries
                                            start_period
                                        }
                                        volumes
                                    }
                                    portMappings {
                                        containerPort
                                        hostPort
                                    }
                                }
                            }
                            lastEvaluatedKey
                        }
                    }
                    """
                )
                node_result = await client.execute(
                    query, variable_values={"tenant": TENANT, "name": node}
                )
            if node_result["SearchNodes"]["lastEvaluatedKey"]:
                raise Exception(f"More than one configuration found for {node}")
            if not node_result["SearchNodes"]["items"]:
                raise Exception(f"No configuration found for {node}")
            node_config = node_result["SearchNodes"]["items"][0]
        # Create the node tracking
        NODES[node] = NODES.get(node, {})
        pull_args = {}
        docker_config = node_config["managedNodeType"]["dockerConfig"]
        username = docker_config.get("username")
        password = docker_config.get("password")
        image_url = docker_config["imageUrl"]
        image_ref = Reference.parse(image_url)
        # If this is an ECR repository, get the username/password from ECR
        if image_ref.repository["domain"] and ECR_PATTERN.match(
            image_ref.repository["domain"]
        ):
            if username or password:
                raise Exception("Username and password are mutually exclusive to using an ecr repo.")
            authorization_data = await _run_in_executor(
                functools.partial(
                    ECR.get_authorization_token,
                    registryIds=[image_ref.repository["domain"].split(".")[0]],
                )
            )
            username, password = (
                b64decode(authorization_data["authorizationData"][0]["authorizationToken"]).decode().split(":")
            )

        if (username, password) and None in (username, password):
            raise Exception("You must provide both username AND password for private registries or neither for public registries")

        # Add the auth_config to the pull args if both username and password are present
        if username and password:
            pull_args["auth_config"] = {"username": username, "password": password}
        # Now let's pull the actual image
        image = NODES[node]["image"] = await _run_in_executor(
            functools.partial(DOCKER.images.pull, image_url, **pull_args)
        )
        # Add volume tracking if doesn't exist
        NODES[node]["volumes"] = NODES[node].get("volumes", {})
        mounts = []
        # Create the volumes if we have host mounts
        if volumes := node_config["managedNodeType"].get("volumes"):
            named_volumes = await asyncio.gather(
                *[
                    _run_in_executor(
                        functools.partial(
                            DOCKER.volumes.create,
                            name=sha256(f"{node}{volume}".encode()).hexdigest(),
                        )
                    )
                    for volume in volumes
                ]
            )
            for index in range(len(volumes)):
                NODES[node]["volumes"][named_volumes[index].id] = named_volumes[index]
                mounts.append(
                    Mount(volumes[index], named_volumes[index].id, type="volume")
                )
        healthcheck = None
        if node_healthcheck := node_config["managedNodeType"].get("healthcheck"):
            healthcheck = Healthcheck(
                test=node_healthcheck["test"],
                interval=convert_healthcheck_time(node_healthcheck["interval"]),
                timeout=convert_healthcheck_time(node_healthcheck["timeout"]),
                retries=node_healthcheck["retries"],
                start_period=convert_healthcheck_time(node_healthcheck["start_period"]),
            )
        # Start the container
        utc_now = datetime.utcnow()
        NODES[node]["container"] = await _run_in_executor(
            functools.partial(
                DOCKER.containers.run,
                image.id,
                detach=True,
                environment={**NODE_ENV_VARS, **{"NODE_NAME": node}},
                healthcheck=healthcheck,
                log_config=LogConfig(
                    type="awslogs",
                    config={
                        "awslogs-group": node_config["logGroupName"],
                        "awslogs-multiline-pattern": "^\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]",
                        "awslogs-stream": f"{utc_now.year}/{utc_now.month:02}/{utc_now.day:02}/{token_hex(16)}",
                    },
                ),
                mounts=mounts
                + [
                    Mount(
                        host_mount["containerPath"], host_mount["hostPath"], type="bind"
                    )
                    for host_mount in node_config.get("hostMounts", [])
                ],
                ports={
                    int(port_mapping["containerPort"]): int(port_mapping["hostPort"])
                    for port_mapping in node_config["portMappings"]
                },
                restart_policy={"Name": "unless-stopped"},
            ),
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        getLogger().exception(f"Error occurred starting {node}")


async def remove_node(node: str) -> None:
    await stop_node(node)
    if node in NODES:
        try:
            getLogger().info("Removing node {node}")
            remove_tasks = []
            if volumes := NODES[node]["volumes"].values():
                for volume in volumes:
                    remove_tasks.append(
                        asyncio.create_task(
                            _run_in_executor(
                                functools.partial(volume.remove, force=True),
                            )
                        )
                    )
            if image := NODES[node].get("image"):
                remove_tasks.append(
                    asyncio.create_task(
                        _run_in_executor(
                            functools.partial(
                                DOCKER.images.remove, image=image.id, force=True
                            ),
                        )
                    )
                )
            if remove_tasks:
                await asyncio.gather(*remove_tasks)
            del NODES[node]
        except asyncio.CancelledError:
            raise
        except Exception:
            getLogger().exception(f"Error occurred removing {node}")


async def run() -> None:
    getLogger().info(f'Starting app {environ["APP_NAME"]}')
    claims = jwt.get_unverified_claims(TOKEN_FETCHER.id_token)
    if "tenants" not in claims:
        raise Exception('Invalid token, does not contain claim "tenants"')
    tenants = json.loads(claims["tenants"])
    if len(tenants) != 1:
        raise Exception('Either no tenants in "tenants" claim or too many')
    global TENANT
    TENANT = list(tenants.keys())[0]

    await initialize_app(environ["APP_NAME"])

    async with Client(
        transport=AppSyncWebsocketsTransport(
            url=environ["APPSYNC_ENDPOINT"],
            authorization=AppSyncOIDCAuthorization(
                urlparse(environ["APPSYNC_ENDPOINT"]).netloc, TOKEN_FETCHER.id_token
            ),
            ssl=_create_unverified_context(),
        ),
    ) as client:
        subscription = gql(
            """
            subscription receiveAppNotifications($tenant: String!, $app: String!) {
                appNotifications(tenant: $tenant, app: $app) {
                    itemType
                    operation
                    node
                }
            }
            """
        )
        getLogger().info(
            f'Subscribing to notifications for managed app {environ["APP_NAME"]}'
        )
        async for notification in client.subscribe(
            subscription,
            variable_values={"tenant": TENANT, "app": environ["APP_NAME"]},
        ):
            if notification["itemType"] in ("app", "tenant"):
                if notification["operation"] == "REMOVE":
                    # app or tenant is being shutdown, let's exit
                    break
            elif notification["itemType"] == "node" and "node" in notification:
                if notification["operation"] == "REMOVE":
                    # node is being removed, remove it
                    getLogger().info(f'Node {notification["node"]} has been removed')
                    await remove_node(notification["node"])
                else:
                    # new node or node changed, let's start it up
                    getLogger().info(
                        f'Node {notification["node"]} has been {"changed" if notification["operation"] == "MODIFY" else "added"}'
                    )
                    await start_node(notification["node"])
    getLogger().info(f'Stopping app {environ["APP_NAME"]}')
    await asyncio.gather(*[stop_node(node) for node in NODES.keys()])


def main():
    aiorun.run(run(), stop_on_unhandled_errors=True)
