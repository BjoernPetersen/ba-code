# NOTE: the build context should be the repository root!

FROM dart:2.15 AS builder

WORKDIR /app

# Copy app source code and AOT compile it.
COPY . .

WORKDIR /app/server

RUN dart pub get

RUN dart run build_runner build

RUN dart compile exe bin/main.dart -o bin/main

FROM scratch

COPY --from=builder /runtime/ /
# Copy compiled application into final image
COPY --from=builder /app/server/bin/main /app/bin/

ARG build
ENV BUILD=$build

EXPOSE 8080

# Start server.
CMD ["/app/bin/main"]
