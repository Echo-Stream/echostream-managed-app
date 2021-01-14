import asyncio
import functools
import json
from base64 import b64decode
from datetime import datetime
from hashlib import sha256
from logging import INFO, WARNING, Formatter, getLogger
from os import environ
from secrets import token_hex
from ssl import _create_unverified_context
from re import compile
from time import gmtime
from typing import Any, Dict
from urllib.parse import urlparse

import aiorun
from boto3 import client
from cognitoinator import TokenFetcher
from docker import from_env
from docker.types import LogConfig, Mount
from docker_image.reference import Reference
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from jose import jwt
from watchtower import CloudWatchLogHandler

from .appsync_websockets import AppSyncOIDCAuthorization, AppSyncWebsocketsTransport

# TODO: comment in gql here to prevent log spam
for name in [
    "boto",
    "urllib3",
    "s3transfer",
    "boto3",
    "botocore",
    "nose",
    # "gql.transport.aiohttp",
    # "gql.transport.websockets",
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


async def run_in_executor(func):
    return await asyncio.get_running_loop().run_in_executor(
        None,
        func,
    )


async def initalize_app() -> None:
    # Clean up hanging containers and images, if any
    await asyncio.gather(
        run_in_executor(DOCKER.containers.prune),
        run_in_executor(
            functools.partial(DOCKER.images.prune, filters={"dangling": True})
        ),
    )
    # TODO: search for app here, start nodes
    pass


async def stop_node(node: str) -> None:
    if container := NODES.get(node, {}).get("container"):
        getLogger().info("Stopping node {node}")
        try:
            # Stop the container
            await run_in_executor(
                functools.partial(container.stop, timeout=30),
            )
            # Wait for the container to actually stop
            await run_in_executor(
                functools.partial(container.wait, timeout=30),
            )
            # Remove the container, forcibly if necessary
            await run_in_executor(
                functools.partial(container.remove, force=True),
            )
            # Remove the tracked reference to the container
            del NODES[node]["container"]
        except asyncio.CancelledError:
            raise
        except Exception:
            getLogger().exception(f"Error occurred stopping {node}")


async def start_node(node: str):
    await stop_node(node)
    getLogger().info("Starting node {node}")
    try:
        config = {}
        # TODO: get config here
        # Create the node tracking
        NODES[node] = NODES.get(node, {})
        pull_args = {}
        docker_config = config["managedNodeType"]["dockerConfig"]
        username = docker_config.get("username")
        password = docker_config.get("passowrd")
        image_url = docker_config["imageUrl"]
        image_ref = Reference.parse(image_url)
        # If this is an ECR repository, get the username/password from ECR
        if image_ref.repository["domain"] and ECR_PATTERN.match(
            image_ref.repository["domain"]
        ):
            authorization_data = await run_in_executor(
                functools.partial(
                    ECR.get_authorization_token,
                    registryIds=[image_ref.repository["domain"].split(".")[0]],
                )
            )
            username, password = (
                b64decode(authorization_data["authorizationToken"]).decode().split(":")
            )
        # Add the auth_config to the pull args if both username and password are present
        if username and password:
            pull_args["auth_config"] = {"username": username, "password": password}
        # Now let's pull the actual image
        image = NODES[node]["image"] = await run_in_executor(
            functools.partial(DOCKER.images.pull, image_url, **pull_args)
        )
        # Add volume tracking if doesn't exist
        NODES[node]["volumes"] = NODES[node].get("volumes", {})
        mounts = []
        # Create the volumes if we have host mounts
        if volumes := config["managedNodeType"].get("volumes"):
            named_volumes = await asyncio.gather(
                *[
                    run_in_executor(
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
        # Start the container
        utc_now = datetime.utcnow()
        NODES[node]["container"] = await run_in_executor(
            functools.partial(
                DOCKER.containers.run,
                image.id,
                log_config=LogConfig(
                    type="awslogs",
                    config={
                        "awslogs-region": environ["AWS_DEFAULT_REGION"],
                        "awslogs-group": config["logGroupName"],
                        "awslogs-multiline-pattern": "^\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]",
                        "awslogs-stream": f"{utc_now.year}/{utc_now.month:02}/{utc_now.day:02}/{token_hex(16)}",
                    },
                ),
                mounts=mounts,
                restart_policy={
                    "Name": "always",
                },
            ),
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        getLogger().exception(f"Error occurred starting {node}")


async def remove_node(node: str) -> None:
    await stop_node(node)
    try:
        if node in NODES:
            getLogger().info("Removing node {node}")
            remove_tasks = []
            if volumes := NODES[node]["volumes"].values():
                for volume in volumes:
                    remove_tasks.append(
                        asyncio.create_task(
                            run_in_executor(
                                functools.partial(volume.remove, force=True),
                            )
                        )
                    )
            if image := NODES[node].get("image"):
                remove_tasks.append(
                    asyncio.create_task(
                        run_in_executor(
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


async def run():
    getLogger().info(f'Starting app {environ["APP_NAME"]}')
    claims = jwt.get_unverified_claims(TOKEN_FETCHER.id_token)
    if "tenants" not in claims:
        raise Exception('Invalid token, does not contain claim "tenants"')
    tenants = json.loads(claims["tenants"])
    if len(tenants) != 1:
        raise Exception('Either no tenants in "tenants" claim or too many')
    global TENANT
    TENANT = list(tenants.keys())[0]

    # TODO: Initialize app here

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
        getLogger().info(f'Subscribing to notifications in {environ["APP_NAME"]}')
        async for result in client.subscribe(
            subscription,
            variable_values={"tenant": TENANT, "app": environ["APP_NAME"]},
        ):
            # TODO: Process results here
            getLogger().info(f"{result}")
    getLogger().info(f'Stopping app {environ["APP_NAME"]}')
    await asyncio.gather(*[stop_node(node) for node in NODES.keys()])


def main():
    aiorun.run(run(), stop_on_unhandled_errors=True)
