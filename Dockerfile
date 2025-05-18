FROM golang:1.24.3-bookworm AS dependencies

RUN groupadd --system -g 1000 builder && \
  useradd --system --uid 1000 -g builder builder

USER builder

WORKDIR /home/builder

RUN --mount=type=ssh,uid=1000 \
  --mount=type=cache,uid=1000,gid=1000,target=/go/pkg/mod \
  --mount=type=bind,source=go.sum,target=go.sum \
  --mount=type=bind,source=go.mod,target=go.mod \
  go mod download -x && go mod verify

#######################################################################################
# Build the service
#######################################################################################

FROM dependencies AS build

ENV CGO_ENABLED=1

RUN --mount=type=ssh,uid=1000 \
  --mount=type=cache,uid=1000,gid=1000,target=/go/pkg/mod \
  --mount=type=bind,source=go.sum,target=go.sum \
  --mount=type=bind,source=go.mod,target=go.mod \
  --mount=type=bind,source=main.go,target=main.go \
  --mount=type=bind,source=internal,target=internal \
  go build .

#######################################################################################
# Run the service
#######################################################################################

FROM debian:bookworm-slim

RUN groupadd --system -g 1000 runner && \
  useradd --system --uid 1000 -g runner runner

RUN apt update && \
  apt install -y ca-certificates

RUN mkdir /srv/bin && chown -R runner:runner /srv/bin

USER runner
WORKDIR /srv/bin

COPY --from=build /home/builder/atproto-oauth2-go-example /srv/bin/atproto-oauth2-go-example

ENV PATH="$PATH:/srv/bin"

ARG GIT_COMMIT="unknown"
ARG BUILD_TIME="unknown"

LABEL org.opencontainers.image.title="Demo ATProto Go Example"
LABEL org.opencontainers.image.description="This container image contains the Demo ATProto Go Example."
LABEL org.opencontainers.image.version="${GIT_COMMIT}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created=${BUILD_TIME}
LABEL org.opencontainers.image.authors="mickaelvieira.com <mickael@mickaelvieira.com>"
LABEL org.opencontainers.image.vendor="mickaelvieira.com"
LABEL org.opencontainers.image.url="https://github.com/mickaelvieira/atproto-oauth2-go-example"
LABEL org.opencontainers.image.source="https://github.com/mickaelvieira/atproto-oauth2-go-example"
LABEL org.opencontainers.image.documentation="https://github.com/mickaelvieira/atproto-oauth2-go-example"

EXPOSE 9000

ENTRYPOINT [ "atproto-oauth2-go-example" ]
