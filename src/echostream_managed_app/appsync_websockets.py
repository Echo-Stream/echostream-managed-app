import hmac
import json
from abc import ABC, abstractmethod
from asyncio import CancelledError, wait_for, TimeoutError, ensure_future
from base64 import b64encode
from datetime import datetime
from hashlib import sha256
from logging import getLogger
from ssl import SSLContext
from typing import Any, AsyncGenerator, Dict, Optional, Union, cast

from boto3.session import Session
from gql.transport.websockets import ListenerQueue, WebsocketsTransport
from graphql import DocumentNode, ExecutionResult, print_ast
from websockets import connect as wsconnect
from websockets.typing import Subprotocol
from websockets.exceptions import ConnectionClosed
from gql.transport.exceptions import (
    TransportAlreadyConnected,
    TransportProtocolError,
)

_LOG = getLogger(__name__)


class AppSyncAuthorization(ABC):
    def on_connect(self) -> str:
        return b64encode(
            json.dumps(self.on_subscribe(), separators=(",", ":")).encode()
        ).decode()

    @abstractmethod
    def on_subscribe(self, data: Optional[str] = None) -> Dict:
        raise NotImplementedError()

    def _encodeHeader(self, header: Dict) -> str:
        return b64encode(json.dumps(header, separators=(",", ":")).encode()).decode()


class AppSyncApiKeyAuthorization(AppSyncAuthorization):
    def __init__(self, host: str, api_key: str) -> None:
        self.host = host
        self.api_key = api_key

    def on_subscribe(self, data: Optional[str] = None) -> Dict:
        return {"host": self.host, "x-api-key": self.api_key}


class AppSyncOIDCAuthorization(AppSyncAuthorization):
    def __init__(self, host: str, token: str) -> None:
        self.host = host
        self.token = token

    def on_subscribe(self, data: Optional[str] = None) -> Dict:
        return {"host": self.host, "Authorization": self.token}


class AppSyncIAMAuthorization(AppSyncAuthorization):
    def __init__(self, host: str) -> None:
        self.host = host
        self.session = Session()
        self.region = self.host.split(".")[2]
        self.signed_headers = (
            "accept;content-encoding;content-type;host;x-amz-date;x-amz-security-token"
        )

    def on_subscribe(self, data: Optional[str] = None) -> Dict:
        utc_now = datetime.utcnow()
        amz_date = utc_now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = utc_now.strftime("%Y%m%d")
        credentials = self.session.get_credentials()
        return {
            "accept": "application/json, text/javascript",
            "content-encoding": "amz-1.0",
            "content-type": "application/json; charset=UTF-8",
            "host": self.host,
            "x-amz-date": amz_date,
            "X-Amz-Security-Token": credentials.token,
            "Authorization": self._sigv4(amz_date, date_stamp, credentials, data),
        }

    def _sigv4(
        self, amz_date, date_stamp, credentials, data: Optional[str] = None
    ) -> str:
        def getSignatureKey(key, date_stamp, regionName, serviceName):
            def sign(key, msg):
                return hmac.new(key, msg.encode("utf-8"), sha256).digest()

            kDate = sign(f"AWS4 {key}".encode("utf-8"), date_stamp)
            kRegion = sign(kDate, regionName)
            kService = sign(kRegion, serviceName)
            kSigning = sign(kService, "aws4_request")
            return kSigning

        # Create a date for headers and the credential string
        credentials_scope = f"{date_stamp}/{self.region}/appsync/aws4_request"

        canonical_request = f"""POST
        /graphql{"/connect" if data else ""}

        accept:application/json, text/javascript
        content-encoding:amz-1.0
        content-type:application/json; charset=UTF-8
        host:{self.host}
        x-amz-date:{amz_date}
        x-amz-security-token:{credentials.token}
        {self.signed_headers}
        {sha256((data or "{}").encode('utf-8')).hexdigest()}
        """

        string_to_sign = f"""AWS4-HMAC-SHA256
        {amz_date}
        {credentials_scope}
        {sha256(canonical_request.encode('utf-8')).hexdigest()}"""

        signature = hmac.new(
            getSignatureKey(
                credentials.secret_key,
                date_stamp,
                self.region,
                "appsync",
            ),
            string_to_sign.encode("utf-8"),
            sha256,
        ).hexdigest()
        return f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{credentials_scope},SignedHeaders={self.signed_headers},Signature={signature}"


class AppSyncWebsocketsTransport(WebsocketsTransport):
    def __init__(
        self,
        url: str,
        authorization: AppSyncAuthorization,
        ssl: Union[SSLContext, bool] = False,
        connect_timeout: int = 10,
        close_timeout: int = 10,
        ack_timeout: int = 10,
        connect_args: Dict[str, Any] = {},
    ) -> None:
        self.authorization = authorization
        super().__init__(
            url,
            ssl=ssl,
            connect_timeout=connect_timeout,
            close_timeout=close_timeout,
            ack_timeout=ack_timeout,
            connect_args=connect_args,
        )

    async def _wait_start_ack(self) -> None:
        """Wait for the start_ack message. Keep alive messages are ignored"""

        while True:
            answer_type = str(json.loads(await self._receive()).get("type"))

            if answer_type == "start_ack":
                return

            if answer_type != "ka":
                raise TransportProtocolError(
                    "AppSync server did not return a start ack"
                )

    async def _send_start_and_wait_ack(
        self,
        document: DocumentNode,
        variable_values: Optional[Dict[str, str]] = None,
    ) -> int:
        query_id = self.next_query_id
        self.next_query_id += 1

        data = {"query": print_ast(document)}
        if variable_values:
            data["variables"] = variable_values
        data = json.dumps(data, separators=(",", ":"))

        await self._send(
            json.dumps(
                {
                    "id": str(query_id),
                    "type": "start",
                    "payload": {
                        "data": data,
                        "extensions": {
                            "authorization": self.authorization.on_subscribe(data)
                        },
                    },
                },
                separators=(",", ":"),
            )
        )

        # Wait for the connection_ack message or raise a TimeoutError
        await wait_for(self._wait_start_ack(), self.ack_timeout)

        # Create a task to listen to the incoming websocket messages
        self.receive_data_task = ensure_future(self._receive_data_loop())

        return query_id

    async def connect(self) -> None:
        """Coroutine which will:

        - connect to the websocket address
        - send the init message
        - wait for the connection acknowledge from the server
        - create an asyncio task which will be used to receive
          and parse the websocket answers

        Should be cleaned with a call to the close coroutine
        """

        GRAPHQLWS_SUBPROTOCOL: Subprotocol = cast(Subprotocol, "graphql-ws")

        _LOG.debug("connect: starting")

        if self.websocket is None and not self._connecting:

            # Set connecting to True to avoid a race condition if user is trying
            # to connect twice using the same client at the same time
            self._connecting = True

            # If the ssl parameter is not provided,
            # generate the ssl value depending on the url
            ssl: Optional[Union[SSLContext, bool]]
            if self.ssl:
                ssl = self.ssl
            else:
                ssl = True if self.url.startswith("wss") else None

            # Set default arguments used in the websockets.connect call
            connect_args: Dict[str, Any] = {
                "ssl": ssl,
                "extra_headers": self.headers,
                "subprotocols": [GRAPHQLWS_SUBPROTOCOL],
            }

            # Adding custom parameters passed from init
            connect_args.update(self.connect_args)

            # Connection to the specified url
            # Generate a TimeoutError if taking more than connect_timeout seconds
            # Set the _connecting flag to False after in all cases
            try:
                self.websocket = await wait_for(
                    wsconnect(
                        f'{self.url.replace("https","wss").replace("appsync-api","appsync-realtime-api")}?header={self.authorization.on_connect()}&payload=e30=',
                        **connect_args,
                    ),
                    self.connect_timeout,
                )
            finally:
                self._connecting = False

            self.next_query_id = 1
            self.close_exception = None
            self._wait_closed.clear()

            # Send the init message and wait for the ack from the server
            # Note: This will generate a TimeoutError
            # if no ACKs are received within the ack_timeout
            try:
                await self._send_init_message_and_wait_ack()
            except ConnectionClosed as e:
                raise e
            except (TransportProtocolError, TimeoutError) as e:
                await self._fail(e, clean_close=False)
                raise e

        else:
            raise TransportAlreadyConnected("Transport is already connected")

        _LOG.debug("connect: done")

    async def subscribe(
        self,
        document: DocumentNode,
        variable_values: Optional[Dict[str, str]] = None,
        send_stop: Optional[bool] = None,
    ) -> AsyncGenerator[ExecutionResult, None]:
        # Send the query and receive the id
        query_id: int = await self._send_start_and_wait_ack(document, variable_values)

        # Create a queue to receive the answers for this query_id
        listener = ListenerQueue(query_id, send_stop=(send_stop is True))
        self.listeners[query_id] = listener

        # We will need to wait at close for this query to clean properly
        self._no_more_listeners.clear()

        try:
            # Loop over the received answers
            while True:

                # Wait for the answer from the queue of this query_id
                # This can raise a TransportError or ConnectionClosed exception.
                answer_type, execution_result = await listener.get()

                # If the received answer contains data,
                # Then we will yield the results back as an ExecutionResult object
                if execution_result is not None:
                    yield execution_result

                # If we receive a 'complete' answer from the server,
                # Then we will end this async generator output without errors
                elif answer_type == "complete":
                    _LOG.debug(
                        f"Complete received for query {query_id} --> exit without error"
                    )
                    break

        except (CancelledError, GeneratorExit) as e:
            _LOG.debug("Exception in subscribe: " + repr(e))
            if listener.send_stop:
                await self._send_stop_message(query_id)
                listener.send_stop = False

        finally:
            del self.listeners[query_id]
            if len(self.listeners) == 0:
                self._no_more_listeners.set()
