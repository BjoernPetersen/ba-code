# Server Module

The server uses the `shelf` library to expose a small HTTP API on port 8080,
which allows clients to try the OPAQUE protocol.
See the [`server.dart`](lib/src/server.dart) module as an entrypoint to the application.

## Building

The module can either be built with Docker or by directly using the Dart SDK.

### Build using Docker

Make sure Docker is installed and the Docker daemon is running.
Then execute the following command in the module directory to build the opaque Docker image:

```
docker build -t opaque -f Dockerfile ..
```

Now a Docker image with the tag `opaque:latest` is available on your local machine.
To run it and expose its port 8080 on the host machine, execute:

```
docker run --rm -p 8080:8080 -d opaque
```

### Build using the Dart SDK

Make sure the Dart SDK version 2.15 or higher is installed.
Then execute the following commands:

- `dart pub get`
  - Resolves dependencies
- `dart run build_runner build`
  - Performs code generation for HTTP routing
- `dart compile exe bin/main.dart -o server`
  - Creates a `server` executable in the current directory
