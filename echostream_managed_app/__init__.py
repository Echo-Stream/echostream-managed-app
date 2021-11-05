from __future__ import annotations

import asyncio
import functools
from base64 import b64decode
from datetime import datetime
from logging import INFO, WARNING, Formatter, getLogger
from logging.handlers import WatchedFileHandler
from os import environ, system
from time import gmtime
from typing import TYPE_CHECKING, Any, Callable, Literal, TypedDict, Union
from uuid import uuid4

import boto3
import docker
import simplejson as json
from docker.client import DockerClient
from docker.models.containers import Container
from docker.models.images import Image
from docker.models.networks import Network
from docker.types.containers import Healthcheck, LogConfig
from docker.types.services import DriverConfig, Mount
from echostream_node import Message, AuditRecord
from echostream_node.asyncio import CognitoAIOHTTPTransport, Node
from gql.client import Client as GqlClient
from gql.gql import gql
from pycognito import Cognito
from sdnotify import SystemdNotifier

if TYPE_CHECKING:
    from mypy_boto3_ecr.client import ECRClient
    from mypy_boto3_ecr_public.client import ECRPublicClient
else:
    ECRClient = object
    ECRPublicClient = object

getLogger().setLevel(environ.get("LOGGING_LEVEL") or INFO)
watched_file_handler = WatchedFileHandler(
    filename="/var/log/echostream/echostream-managed-app.log"
)
formatter = Formatter(
    fmt="[%(levelname)s] %(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
)
formatter.converter = gmtime
watched_file_handler.setFormatter(formatter)
getLogger().addHandler(watched_file_handler)
getLogger("gql.transport.aiohttp").setLevel(environ.get("LOGGING_LEVEL") or WARNING)
getLogger("gql.transport.awsappsyncwebsockets").setLevel(
    environ.get("LOGGING_LEVEL") or WARNING
)

SYSTEMD = SystemdNotifier()


async def _run_in_executor(func: Callable, *args, **kwargs) -> Any:
    return await asyncio.get_running_loop().run_in_executor(
        None,
        functools.partial(func, *args, **kwargs),
    )


class AtBy(TypedDict):
    at: datetime
    by: str


class Change(TypedDict, total=False):
    datetime: str
    lastModified: AtBy
    new: dict[str, Any]
    old: dict[str, Any]
    system: bool
    tenant: str


class ManagedNodeType(TypedDict, total=False):
    healthcheck: dict[str, Union[list[str], int]]
    imageUri: str


class Mount(TypedDict, total=False):
    consistency: Literal["cached", "consistent", "delegated"]
    labels: str
    noCopy: bool
    options: str
    source: str
    target: str


class Port(TypedDict, total=False):
    containerPort: int
    hostAddress: str
    hostPort: int
    protocol: Literal["sctp", "tcp", "udp"]


class ManagedNodeContainer(TypedDict, total=False):
    managedNodeType: ManagedNodeType
    mounts: list[Mount]
    ports: list[Port]


class ManagedNodeMetaData(TypedDict, total=False):
    managedNodeType: dict[str, str]
    receiveMessageType: dict[str, str]
    sendMessageType: dict[str, str]


class ManagedNode:

    _GET_MANAGED_NODE_CONTAINER_GQL = gql(
        """
        query getManagedNodeContainer($name: String!, $tenant: $String!) {
            GetNode(name: $name, tenant: $tenant) {
                ... on ManagedNode {
                    managedNodeType {
                        imageUri
                        healthcheck {
                            interval
                            retries
                            startPeriod
                            test
                            timeout
                        }
                    }
                    mounts {
                        consistency
                        labels
                        noCopy
                        options
                        readOnly
                        source
                        target
                    }
                    ports {
                        containerPort
                        hostAddress
                        hostPort
                        protocol
                    }
                }
            }
        }
        """
    )

    _GET_MANAGED_NODE_META_DATA_GQL = gql(
        """
        query getManagedNodeMetaData($name: String!, $tenant: $String!) {
            GetNode(name: $name, tenant: $tenant) {
                ... on ManagedNode {
                    managedNodeType {
                        name
                    }
                    receiveMessageType {
                        name
                    }
                    sendMessageType {
                        name
                    }
                }
            }
        }
        """
    )

    def __init__(self, name: str, managed_app: ManagedApp) -> None:
        self.__managed_app = managed_app
        self.__container: Container = None
        self.__lock = asyncio.Lock()
        self.__name = name
        data: ManagedNodeMetaData = self.__managed_app.gql_client.execute(
            self._GET_MANAGED_NODE_META_DATA_GQL,
            variable_values=dict(name=name, tenant=managed_app.tenant),
        )["GetNode"]
        self.__managed_node_type = data["managedNodeType"]["name"]
        self.__receive_message_type = data.get("receiveMessageType", {}).get("name")
        self.__send_message_type = data.get("sendMessageType", {}).get("name")

    @property
    def managed_node_type(self) -> str:
        return self.__managed_node_type

    @property
    def name(self) -> str:
        return self.__name

    @property
    def receive_message_type(self) -> str:
        return self.__receive_message_type

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    @property
    def send_message_type(self) -> str:
        return self.__send_message_type

    async def start(self) -> None:
        async with self.__lock:
            async with self.__managed_app.gql_client as session:
                data: ManagedNodeContainer = await session.execute(
                    self._GET_MANAGED_NODE_CONTAINER_GQL,
                    variable_values=dict(
                        name=self.name, tenant=self.__managed_app.tenant
                    ),
                )["GetNode"]
            image_uri = data["managedNodeType"]["imageUri"]
            registry = image_uri.split("/")[0]
            if registry == "public.ecr.aws":
                authorization_token = self.__managed_app.ecr_public_client.get_authorization_token()[
                    "authorizationData"
                ][
                    "authorizationToken"
                ]
            else:
                account_id = registry.split(".")[0]
                authorization_token = (
                    self.__managed_app.ecr_client.get_authorization_token(
                        registryIds=[account_id]
                    )["authorizationData"][0]["authorizationToken"]
                )
            username, password = (
                b64decode(authorization_token).decode().split(":")
            )
            await _run_in_executor(
                self.__managed_app.docker_client.login,
                username=username,
                password=password,
                registry=registry,
            )
            image: Image = await _run_in_executor(
                self.__managed_app.docker_client.images.pull, repository=image_uri
            )
            utc_now = datetime.utcnow()
            self.__container = await _run_in_executor(
                self.__managed_app.docker_client.containers.run,
                image.id,
                detach=True,
                environment=dict(
                    self.__managed_app.environment,
                    NODE=self.name,
                ),
                healthcheck=Healthcheck(
                    interval=data["managedNodeType"]["healthcheck"]["interval"],
                    retries=data["managedNodeType"]["healthcheck"]["retries"],
                    start_period=data["managedNodeType"]["healthcheck"][
                        "startPeriod"
                    ],
                    test=data["managedNodeType"]["healthcheck"]["test"],
                    timeout=data["managedNodeType"]["healthcheck"]["timeout"],
                )
                if "healthcheck" in data["managedNodeType"]
                else None,
                hostname=self.name,
                log_config=LogConfig(
                    type="awslogs",
                    config={
                        "awslogs-group": f"{self.__managed_app.log_group_name}/node/{self.name}",
                        "awslogs-multiline-pattern": "^\[(CRITICAL|DEBUG|ERROR|INFO|WARNING)\]",
                        "awslogs-stream": f"{utc_now.year}/{utc_now.month:02}/{utc_now.day:02}/{uuid4().hex}",
                    },
                ),
                mounts=[
                    Mount(
                        consistency=mount.get("consistency", "consistent"),
                        driver_config=DriverConfig(
                            "volume", options=json.loads(mount["options"])
                        )
                        if "options" in mount
                        else None,
                        labels=json.loads(mount.get("labels", "null")),
                        no_copy=mount.get("noCopy", False),
                        read_only=mount.get("readOnly", False),
                        source=mount.get("source"),
                        target=mount["target"],
                    )
                    for mount in data.get("mounts", [])
                ],
                name=self.name,
                network=self.__managed_app.docker_network.name,
                ports={
                    f'{port["containerPort"]/port["protocol"]}': (
                        port.get("hostAddress", "0.0.0.0"),
                        port["hostPort"],
                    )
                    for port in data.get("ports", [])
                },
                restart_policy=dict(Name="unless-stopped"),
            )

    async def stop(self) -> None:
        async with self.__lock:
            if self.__container:
                await _run_in_executor(self.__container.stop, timeout=30)
                await _run_in_executor(self.__container.remove, v=False, force=True)
                self.__container: Container = None

class ManagedAppChangeReceiver(Node):
    def __init__(self, *, managed_app: ManagedApp) -> None:
        super().__init__(name=f"{managed_app.name}:Change Receiver")
        self.__managed_app = managed_app

    async def handle_received_message(self, *, message: Message, source: str) -> None:
        change: Change = json.loads(message.body)
        self.put_audit_record(
            AuditRecord(
                attibutes=self.receive_message_auditor(message=change)
                | dict(app=self.__managed_app.name),
                message=message,
                source=source,
            )
        )
        await self.__managed_app._handle_change(change)


class ManagedApp:
    _GET_APP_GQL = gql(
        """
        query getManagedApp($name: String!, $tenant: $String!) {
            GetApp(name: $name, tenant: $tenant) {
                ... on ManagedApp {
                    nodes {
                        name
                    }
                }
            }
        """
    )

    def __init__(
        self,
    ) -> None:
        super().__init__()
        self.__docker_client = docker.from_env()
        self.__cognito = Cognito(
            client_id=environ["CLIENT_ID"],
            user_pool_id=environ["USER_POOL_ID"],
            username=environ["USERNAME"],
        )
        self.__cognito.authenticate(password=environ["PASSWORD"])
        self.__gql_client = GqlClient(
            fetch_schema_from_transport=True,
            transport=CognitoAIOHTTPTransport(
                self.__cognito,
                environ["APPSYNC_ENDPOINT"],
            ),
        )
        self.__name: str = environ["APP"]
        self.__tenant: str = environ["TENANT"]
        self.__ecr_client: ECRClient = boto3.client("ecr")
        self.__ecr_public_client: ECRPublicClient = boto3.client("ecr-public")
        self.__nodes: dict[str, ManagedNode] = dict()

    async def _handle_change(self, change: Change) -> None:
        new = change.get("new")
        old = change.get("old")
        if (new or old)["type"] == "ManagedApp" and (new or old)["name"] == self.name:
            if new and not old:
                # Got the creation method, nothing to do
                return
            if new and new.get("removed"):
                # Our app has been removed, shutdown the host VM
                system("shutdown now")
            if new and old:
                # the app has changed, restart all nodes
                await asyncio.gather(*list(map(ManagedNode.restart, self.__nodes.values())))
        elif (new or old)["type"] == "ManagedNode" (new or old)["app"] == self.name:
            if new and not old:
                # We have a new node to start
                self.__nodes[new["name"]] = node = (ManagedNode(new["name"], self))
                await node.start()
            elif (new and new["removed"]) or (old and not new):
                # Node was removed, stop it
                if node := self.__nodes.pop((new or old)["name"], None):
                    await node.stop()
            else:
                # The node changed, restart it
                if node := self.__nodes.get(new["name"]):
                    await node.restart()
                else:
                    getLogger().critical(f'No node named {new["name"]} found, cannot restart')
        elif (new or old)["type"] == "ManagedNodeType" and (new and old):
            restart_nodes: list[ManagedNode] = list()
            for node in self.__nodes.values():
                if node.managed_node_type == new["name"]:
                    # Managed node type changed for this node, restart
                    restart_nodes.append(node)
            await asyncio.gather(*list(map(ManagedNode.restart, restart_nodes)))
        elif (new or old)["type"] == "MessageType" and (new and old):
            restart_nodes: list[ManagedNode] = list()
            for node in self.__nodes.values():
                if node.receive_message_type == new["name"] or node.send_message_type == new["name"]:
                    # Managed node type changed for this node, restart
                    restart_nodes.append(node)
            await asyncio.gather(*list(map(ManagedNode.restart, restart_nodes)))
        elif (new or old)["type"] == "Edge" and (new is not None) ^ (old is not None):
            # find nodes that use edge and restart them
            edge = new or old
            restart_nodes: list[ManagedNode] = list()
            for node in self.__nodes.values():
                if edge["source"] == node.name or edge["target"] == node.name:
                    restart_nodes.append(node)
            await asyncio.gather(*list(map(ManagedNode.restart, restart_nodes)))
        else:
            getLogger().warning(f"Unknown Change received\n {json.dumps(change, indent=4)}")

    @property
    def docker_client(self) -> DockerClient:
        return self.__docker_client

    @property
    def docker_network(self) -> Network:
        return self.__docker_network

    @property
    def ecr_client(self) -> ECRClient:
        return self.__ecr_client

    @property
    def ecr_public_client(self) -> ECRPublicClient:
        return self.__ecr_public_client

    @property
    def environment(self) -> dict[str, str]:
        return dict(
            APPSYNC_ENDPOINT=environ["APPSYNC_ENDPOINT"],
            CLIENT_ID=environ["CLIENT_ID"],
            PASSWORD=environ["PASSWORD"],
            TENANT=self.tenant,
            USER_POOL_ID=environ["USER_POOL_ID"],
            USERNAME=environ["USERNAME"],
        )

    @property
    def gql_client(self) -> GqlClient:
        return self.__gql_client

    @property
    def log_group_name(self) -> str:
        return environ["LOG_GROUP_NAME"]

    @property
    def name(self) -> str:
        return self.__name

    async def start(self) -> None:
        try:
            networks: list[Network] = await _run_in_executor(self.docker_client.networks.list(names=[self.name]))
            for network in networks:
                if network.name == self.name:
                    self.__docker_network = network
                    break
            if not self.__docker_network:
                self.__docker_network: Network = await _run_in_executor(
                    self.docker_client.networks.create, name=self.name, driver="bridge"
                )
            async with self.gql_client as session:
                data: dict[str, list[dict[str, str]]] = await session.execute(
                    self._GET_APP_GQL,
                    variable_values=dict(name=self.name, tenant=self.tenant),
                )["GetApp"]
            # Create all the managed nodes we found
            for node in data.get("nodes", []):
                self.__nodes[node["name"]] = ManagedNode(node["name"], self)
            # Start them all up
            await asyncio.gather(*list(map(ManagedNode.start, self.__nodes.values())))
            # Notify systemd that we're going...
            SYSTEMD.notify("READY=1")
            # Start up our change receiver
            self.__managed_app_change_receiver_node = ManagedAppChangeReceiver(
                managed_app=self
            )
            await self.__managed_app_change_receiver_node.start()
            await self.__managed_app_change_receiver_node.join()
        finally:
            await asyncio.gather(*list(map(ManagedNode.stop, self.__nodes.values())))

    @property
    def tenant(self) -> str:
        return self.__tenant


async def main() -> None:
    try:
        app = ManagedApp()
        await app.start()
    except asyncio.CancelledError:
        raise
    except Exception:
        getLogger().exception("Error running app")
