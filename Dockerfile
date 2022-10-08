FROM rust:1-alpine3.15 as builder

RUN apk add --update alpine-sdk

WORKDIR /build

COPY . .
RUN cargo build --release

FROM alpine:3.15

ENV USER=app
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/amongusisverysus" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

USER ${USER}

COPY --from=builder /build/target/release/rs-imagehost /bin/rs-imagehost

WORKDIR /data
ENV DATA_DIR=./
ENV ADDRESS=0.0.0.0
ENTRYPOINT ["/bin/rs-imagehost"]
