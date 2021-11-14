# NOTE: the build context should be the repository root!

FROM dart:2.14 AS builder

WORKDIR /app

# Copy app source code and AOT compile it.
COPY . .

WORKDIR /app/server

RUN dart pub get

RUN dart compile exe bin/main.dart -o bin/main

FROM scratch

COPY --from=builder /runtime/ /
COPY --from=builder /app/server/bin/main /app/bin/

ARG build
ENV BUILD=$build

# Start server.
EXPOSE 8080
CMD ["/app/bin/main"]
