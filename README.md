## echostream-managed-app

EchoStream managed app is a part of your EchoStream tenant. It maintains [echostream managed nodes](https://docs.echo.stream/v1/docs/managed-node) throughout their lifecycle. It runs as daemon service on your or your partner's compute environment.

Managed-app can: 
- Pull Docker images from private EchoStream ecr or public.
- Startup, kill, restart docker containers (managed-nodes).
- Runs containers on isolated docker network.
- Upstream the app/node logs to cloudwatch.

More details here: [Managed-app](https://docs.echo.stream/docs/managed-app)